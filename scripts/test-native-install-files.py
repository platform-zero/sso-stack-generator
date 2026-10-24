#!/usr/bin/env python3
"""Real temp-FD selected file transaction + real seven-role projection proofs.

UID/GID/ACL/mount/account/range/FD9/stopped facts are synthetic. The REAL
projector, persistent copier, projection verifier, native-selection planner and
file publisher execute together. No privileged chown or subprocess/host query.
Tests are source/model evidence ONLY, never installed/native acceptance.
"""
import copy
import importlib.util
import os
from pathlib import Path
import shutil
import stat
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


m = load('native_install_files_tested', BASE / 'runtime-generator/podman-ops/native-install-files.py')
f = load('native_install_files_fixture', BASE / 'scripts/test-native-runtime-projection-owner.py')
# Share identical owning implementations so fixture-only UID/mount mocks apply
# consistently. No production permission/ancestry/projection success shim.
m.o = m.v.o
m.p, m.native, m.storage = m.o.p, m.o.native, m.o.storage
m.require, m.Refused = m.o.require, m.o.Refused
f.o, f.p = m.o, m.p
p, n, e = m.p, m.native, m.v.e


class Files(f.Owner):
    def setUp(self):
        previous = os.umask(0o077); self.addCleanup(os.umask, previous)
        super().setUp()
        # Other authorized agents may create unrelated /tmp entries. Those
        # external synthetic ancestors are not this fixture's mutable graph.
        observed_stat, observed_lstat, observed_fstat = os.stat, os.lstat, os.fstat
        test = self
        class StableAncestors:
            def __init__(self, actual):
                self.actual = actual
                if (actual.st_dev, actual.st_ino) in test.ancestor_ids:
                    self.st_size = self.st_mtime_ns = self.st_ctime_ns = 0
                    self.st_nlink = 2
            def __getattr__(self, name): return getattr(self.actual, name)
        patch.object(os, 'stat', side_effect=lambda *a, **kw: StableAncestors(observed_stat(*a, **kw))).start()
        patch.object(os, 'lstat', side_effect=lambda *a, **kw: StableAncestors(observed_lstat(*a, **kw))).start()
        patch.object(os, 'fstat', side_effect=lambda fd: StableAncestors(observed_fstat(fd))).start()
        self.host = self.base / 'host'
        patch.object(m, 'HOST', self.host).start()
        self.stopped_calls = []
        def stopped(release, plan):
            self.assertEqual(release, self.release)
            self.assertEqual(set(plan['scopes']), {'rootful'} | {'rootless-' + name for name in n.IDENTITIES})
            self.stopped_calls.append(copy.deepcopy(plan))
        patch.object(m, 'stopped', side_effect=stopped).start()
        patch.object(subprocess, 'run', side_effect=AssertionError('no subprocess/host queries permitted')).start()
        self.addCleanup(self.close_file_sessions)
        # Model numerical ownership only, confined to this test's real temp FDs.
        def chown(fd, uid, gid):
            path = self.fd_paths[fd]
            self.assertTrue(path.is_relative_to(self.base))
            info = self.raw_fstat(fd)
            self.virtual[info.st_dev, info.st_ino] = uid, gid
            self.mutations.append((path, uid, gid))
        patch.object(os, 'fchown', side_effect=chown).start()
        real_destination = n.destination
        def destination(scope, entry, rel):
            return self.host / real_destination(scope, entry, rel).relative_to('/')
        patch.object(n, 'destination', side_effect=destination).start()
        original_policy = n.directory_policy
        def policy(path, info, actor=None):
            # Exact namespace translation of the fixed /home fixture, NOT a
            # permission relaxation. Original production policy still runs.
            translated = Path('/') / path.relative_to(self.host) if path.is_relative_to(self.host) else path
            original_policy(translated, info, actor)
        patch.object(n, 'directory_policy', side_effect=policy).start()
        for suffix in ('etc/containers/systemd', 'etc/systemd/system', 'home'):
            self.mkdir(self.host / suffix)
        for uid, user in n.IDENTITIES.values():
            account = self.accounts[user]
            for suffix in ('', '.config', '.config/containers', '.config/containers/systemd',
                           '.config/systemd', '.config/systemd/user'):
                path = self.host / 'home' / user / suffix
                self.mkdir(path); self.set_owner(path, uid, account.pw_gid)
                if suffix: path.chmod(0o755)  # Exact actual parent metadata.
        self.manifest['installerStateRoot'] = str(self.install)
        for row in self.rows:
            row['services'] = []; row['persistentServices'] = []
        self.ir = dict(schemaVersion=1, networks={'default': {}}, services={
            'edge': dict(placement='rootful', lifecycle='daemon', target='core', networks=['default'], image='sha256:' + 'a' * 64),
            'webapp': dict(placement='rootless', rootlessDomain='apps', lifecycle='daemon', image='sha256:' + 'b' * 64,
                           environment={'DOMAIN': '${DOMAIN}'}),
            'client': dict(placement='rootless', rootlessDomain='apps', lifecycle='on-demand', build={},
                           image='sha256:' + 'c' * 64, frozenBuildImage='sha256:' + 'c' * 64)})
        apps = next(row for row in self.rows if row['name'] == 'apps')
        apps['services'] = ['webapp', 'client']; apps['persistentServices'] = ['webapp']
        self.emit(self.release, self.ir, self.metadata)
        self.reseal()
        self.provenance(self.release)
        self.prior['inputs'] = self.fingerprint(self.release)
        self.write_records(self.prior)
        projections = {}
        for row in self.rows:
            self.domain, self.row = row['name'], row
            self.state = Path(row['stateRoot']); self.slot = self.state / 'releases' / self.release.name
            self.destination = self.slot / 'runtime'
            self.mkdir(self.slot)
            self.set_owner(self.state / 'releases', row['uid'], self.accounts[row['user']].pw_gid)
            source = self.release / 'quadlet' / ('rootless-' + row['name'])
            for path in source.iterdir():
                self.put(self.slot / 'quadlet' / source.name / path.name, path.read_bytes())
            custody = m.o.prepare_custody(self.install, self.release, self.prior, row['name'])
            new = dict(self.prior, projectionCustody=custody); self.write_records(new)
            proof = m.o.project_and_handoff(self.install, self.release, new, row['name'])
            projections[row['name']] = proof
            value = dict(new, domainRuntimeProjections=copy.deepcopy(projections)); self.write_records(value)
            handoff = e.copy_environment(self.install, self.release, value, row['name'])
            projections[row['name']] = dict(proof, environmentStoreHandoff=handoff)
            self.prior = dict(value, domainRuntimeProjections=copy.deepcopy(projections)); self.write_records(self.prior)
        self.actor_app = next(row for row in self.rows if row['name'] == 'apps')
        self.rel = 'quadlet/rootless-apps/webservices-webapp.container'
        self.path = self.dest(self.rel)
        # Most regression cases publish only five files. The cold-install test
        # below removes ALL fixtures first and exercises every emitted file.
        for entry in n.inventory(self.release).values():
            for rel in entry['files']:
                if rel.endswith('.target'):
                    self.install_file(rel)
        self.mutations.clear()

    def close_file_sessions(self):
        for session in m._sessions.values(): session.close()
        m._sessions.clear()

    def fingerprint(self, release):
        return {name: p.sha((release / name).read_bytes()) if (release / name).exists() else None for name in p.INPUTS}

    def provenance(self, release):
        manifest = (release / 'site/manifest.json').read_bytes()
        self.put(release / 'source-provenance.json', p.encoded(dict(manifestSha256=p.sha(manifest), generatorCommit='a' * 40)))
        self.put(release / 'bundle.json', p.encoded(dict(backend='podman', deploymentMode='standalone',
            irSha256=p.sha((release / 'stack.ir.json').read_bytes()),
            sourceProvenanceSha256=p.sha((release / 'source-provenance.json').read_bytes()))))

    def emit(self, release, ir, metadata):
        self.put(release / 'stack.ir.json', p.encoded(ir))
        self.put(release / 'podman-domains.json', p.encoded(metadata))
        scopes = ['rootful'] + ['rootless-' + row['name'] for row in metadata['domains']]
        for scope in scopes:
            folder = release / 'quadlet' / scope; self.mkdir(folder)
            for subgroup in ('core', 'apps', 'observability'):
                members = ['webservices-' + name + '.service' for name, service in ir['services'].items()
                    if ('rootful' if service['placement'] == 'rootful' else 'rootless-' + service['rootlessDomain']) == scope
                    and service['lifecycle'] != 'on-demand' and service.get('target', 'apps') == subgroup]
                self.put(folder / ('webservices-' + subgroup + '.target'),
                    ('[Unit]\nPartOf=webservices.target\nWants=' + ' '.join(members) + '\n[Install]\nWantedBy=webservices.target\n').encode())
            self.put(folder / 'webservices.target', ('[Unit]\nWants=webservices-core.target webservices-apps.target webservices-observability.target\n'
                '[Install]\nWantedBy=' + ('multi-user.target' if scope == 'rootful' else 'default.target') + '\n').encode())
        for name, service in ir['services'].items():
            scope = 'rootful' if service['placement'] == 'rootful' else 'rootless-' + service['rootlessDomain']
            role = service['lifecycle']
            body = '[Container]\nContainerName=' + name + '\nImage=' + service['image'] + '\n[Install]\n'
            if role != 'on-demand': body += 'WantedBy=webservices-' + service.get('target', 'apps') + '.target\n'
            self.put(release / 'quadlet' / scope / ('webservices-' + name + '.container'), body.encode())
            if 'build' in service:
                self.put(release / 'quadlet' / scope / ('webservices-' + name + '.build'),
                         ('[Build]\nImageTag=localhost/webservices/' + name + ':bundle\n').encode())
        self.put(release / 'quadlet/rootful/webservices-default.network', b'[Network]\nNetworkName=webservices_default\n')

    def dest(self, relative, release=None):
        release = release or self.release
        scope = Path(relative).parts[1]
        uid, user = (0, 'root') if scope == 'rootful' else n.IDENTITIES[scope.removeprefix('rootless-')]
        return n.destination(scope, dict(uid=uid, user=user), relative)

    def install_file(self, relative, release=None):
        release = release or self.release
        path = self.dest(relative, release)
        self.put(path, (release / relative).read_bytes()); path.chmod(0o644)
        scope = Path(relative).parts[1]
        uid = 0 if scope == 'rootful' else n.IDENTITIES[scope.removeprefix('rootless-')][0]
        gid = 0 if not uid else self.accounts[n.IDENTITIES[scope.removeprefix('rootless-')][1]].pw_gid
        self.set_owner(path, uid, gid)
        return path

    def prepare_files(self):
        self.file_custody = m.prepare_custody(self.install, self.release, self.prior)
        return self.file_custody

    def publish_files(self):
        self.new_intent = dict(self.prior, nativeUnitFileCustody=self.file_custody)
        self.write_records(self.new_intent)

    def apply_files(self):
        return m.project_and_handoff(self.install, self.release, self.new_intent)

    def run_files(self):
        self.prepare_files(); self.publish_files(); return self.apply_files()

    def previous_source(self, phase='active', extra=True):
        previous = self.install / 'releases/previous'; self.mkdir(previous)
        for name in p.INPUTS:
            if (self.release / name).exists(): self.put(previous / name, (self.release / name).read_bytes())
        ir, metadata = copy.deepcopy(self.ir), copy.deepcopy(self.metadata)
        if extra:
            ir['services']['oldonly'] = dict(placement='rootful', lifecycle='daemon', image='sha256:' + 'd' * 64)
        self.emit(previous, ir, metadata)
        oldapp = previous / self.rel; oldapp.write_bytes(oldapp.read_bytes() + b'# exact old source\n')
        self.provenance(previous)
        value = dict(schemaVersion=1, phase=phase, release=str(previous), inputs=self.fingerprint(previous), steps=[phase])
        self.put(previous / 'installation-receipt.json', p.encoded(value))
        (self.install / 'current').symlink_to('releases/previous')
        self.prior['previousRelease'] = str(previous) if phase == 'active' else None
        self.write_records(self.prior)
        return previous

    def reject_prepare(self):
        with self.assertRaises((ValueError, OSError, KeyError)):
            self.prepare_files()

    def reject_apply(self):
        with self.assertRaises((ValueError, OSError, KeyError)):
            self.apply_files()

    def test_real_full_cold_publish_all_four_kinds_and_seven_scopes(self):
        for entry in n.inventory(self.release).values():
            for rel in entry['files']:
                self.dest(rel).unlink(missing_ok=True)
        proof = self.run_files()
        expected = {str(self.dest(rel)) for entry in n.inventory(self.release).values() for rel in entry['files']}
        self.assertEqual(set(proof['files']), expected)
        self.assertEqual(set(proof['published']), expected)
        self.assertFalse(proof['activationAuthorized']); self.assertFalse(proof['applicationAcceptance'])
        self.assertFalse(proof['nonInventoryOwned']); self.assertFalse(proof['automaticRestart'])
        for path, pin in proof['files'].items():
            self.assertEqual(stat.S_IMODE(Path(path).stat().st_mode), 0o644)
            self.assertEqual(Path(path).stat().st_uid, pin['uid'])
        self.assertEqual(proof['intentSha256'], p.sha((self.install / '.install-intent.json').read_bytes()))

    def test_prepare_is_readonly_exact_seven_completed_projections(self):
        before = (self.install / '.install-intent.json').read_bytes()
        custody = self.prepare_files()
        self.assertEqual(custody['kind'], 'native-unit-file-custody')
        self.assertEqual(custody['stopOnlyPrevious'], None)
        self.assertEqual(before, (self.install / '.install-intent.json').read_bytes())
        self.assertEqual(self.mutations, []); self.assertFalse(self.path.exists())
        self.assertTrue(self.stopped_calls)

    def test_existing_exact_candidate_inode_untouched(self):
        self.install_file(self.rel)
        before = p.identity(self.path.stat())
        proof = self.run_files()
        self.assertEqual(before, p.identity(self.path.stat()))
        self.assertIn(str(self.path), proof['unchanged'])
        self.assertNotIn(str(self.path), proof['published'])

    def test_previous_exact_replace_and_previous_only_removal(self):
        previous = self.previous_source()
        self.install_file(self.rel, previous)
        oldrel = 'quadlet/rootful/webservices-oldonly.container'
        old = self.install_file(oldrel, previous)
        proof = self.run_files()
        self.assertFalse(old.exists())
        self.assertEqual(proof['removedPreviousOnly'], [str(old)])
        self.assertEqual(self.path.read_bytes(), (self.release / self.rel).read_bytes())
        self.assertEqual(self.file_custody['stopOnlyPrevious']['release'], str(previous))

    def test_retired_failed_current_stop_only_without_restart_claim(self):
        previous = self.previous_source('retired-failed'); self.install_file(self.rel, previous)
        proof = self.run_files()
        self.assertIsNone(self.new_intent['previousRelease'])
        self.assertEqual(proof['stopOnlyPrevious'], str(previous))
        self.assertFalse(proof['automaticRestart'])

    def test_retired_clean_current_stop_only_without_restart_claim(self):
        previous = self.previous_source('retired-clean'); self.install_file(self.rel, previous)
        proof = self.run_files()
        self.assertIsNone(self.new_intent['previousRelease'])
        self.assertEqual(self.file_custody['stopOnlyPrevious']['source']['receipt']['phase'], 'retired-clean')
        self.assertFalse(proof['activationAuthorized'])

    def test_active_current_cannot_be_stop_only_without_active_claim(self):
        self.previous_source(); self.prior['previousRelease'] = None; self.write_records(self.prior)
        self.reject_prepare()

    def test_previous_historical_absent_unmanaged_build_pair_stop_only(self):
        previous = self.previous_source('retired-failed')
        for suffix in ('container', 'build'):
            (previous / 'quadlet/rootless-apps' / ('webservices-client.' + suffix)).unlink()
        self.install_file(self.rel, previous)
        authority = m.storage.authority
        with patch.object(m.storage, 'authority', wraps=authority) as observed:
            proof = self.run_files()
        self.assertTrue(all(call.args[0] == self.release for call in observed.call_args_list))
        old = self.file_custody['stopOnlyPrevious']['source']['scopes']['rootless-apps']
        self.assertNotIn('webservices-client-build.service', old['units'])
        self.assertIn(str(self.dest('quadlet/rootless-apps/webservices-client.build')), proof['files'])

    def test_all_retained_file_fds_close_after_success(self):
        self.prepare_files(); self.publish_files()
        session = m._sessions[str(self.install), str(self.release)]
        held = list(session.fds); self.apply_files()
        self.assertTrue(session.closed)
        for fd in held:
            with self.assertRaises(OSError): self.raw_fstat(fd)

    def test_foreign_differently_named_files_preserved_unread(self):
        sentinels = []
        for name in ('webservices-foreign.container', 'p0-web.service', 'Obelisks.target'):
            path = self.host / 'etc/containers/systemd' / name
            path.symlink_to('/not-read'); sentinels.append(path)
        proof = self.run_files()
        self.assertTrue(all(path.is_symlink() for path in sentinels))
        self.assertFalse(any(str(path) in proof['files'] for path in sentinels))

    def test_no_process_or_helper_path_override(self):
        self.new_intent = dict(self.prior)
        self.reject_apply()
        self.assertFalse(self.path.exists())

    def test_duplicate_prepare_refuses_without_closing_first_custody(self):
        self.prepare_files(); self.reject_prepare(); self.publish_files(); self.apply_files()

    def test_publish_both_records_required(self):
        self.prepare_files(); self.publish_files()
        self.put(self.release / 'installation-receipt.json', p.encoded(self.prior)); self.reject_apply()

    def test_other_journal_changes_refuse(self):
        self.prepare_files(); self.publish_files(); self.new_intent['phase'] = 'units-selected'
        self.write_records(self.new_intent); self.reject_apply()

    def test_custody_forgery_refuses(self):
        self.prepare_files(); self.publish_files(); self.new_intent['nativeUnitFileCustody']['selectionSha256'] = '0' * 64
        self.write_records(self.new_intent); self.reject_apply()

    def test_unsealed_custody_refuses(self):
        self.prepare_files(); self.new_intent = dict(self.prior, nativeUnitFileCustody=self.file_custody); self.reject_apply()

    def test_same_bytes_root_record_inode_aba_refuses_after_seal(self):
        self.prepare_files(); self.publish_files()
        original = m.Session.stage
        def stage(session, path):
            result = original(session, path)
            target = self.install / '.install-intent.json'; body = target.read_bytes()
            target.rename(target.with_name('retained-intent')); self.put(target, body)
            return result
        with patch.object(m.Session, 'stage', stage): self.reject_apply()
        self.assertFalse(self.path.exists())

    def test_full_input_pins_required(self):
        self.prior['inputs'].pop('site/agent-vm.json'); self.write_records(self.prior); self.reject_prepare()

    def test_required_input_hash_drift(self):
        self.put(self.release / 'bundle.json', b'{}\n'); self.reject_prepare()

    def test_unselected_optional_pinned_absent_appears(self):
        self.put(self.release / 'site/agent-vm.json', b'{}\n'); self.reject_prepare()

    def test_source_file_race_after_prepare(self):
        self.prepare_files(); self.publish_files()
        path = self.release / self.rel; path.write_bytes(path.read_bytes() + b'# drift\n'); self.reject_apply()

    def test_source_same_bytes_replaced_after_prepare(self):
        self.prepare_files(); self.publish_files()
        path = self.release / self.rel; body = path.read_bytes(); path.rename(path.with_suffix('.retained'))
        self.put(path, body); self.reject_apply()

    def test_source_extra_inventory_file_refuses(self):
        self.prepare_files(); self.publish_files()
        self.put(self.release / 'quadlet/rootful/webservices-foreign.container', b'foreign'); self.reject_apply()

    def test_source_directory_swapped_refuses(self):
        self.prepare_files(); self.publish_files()
        folder = self.release / 'quadlet/rootful'; folder.rename(folder.with_name('retained'))
        shutil.copytree(folder.with_name('retained'), folder); self.reject_apply()

    def test_source_symlink_refuses(self):
        path = self.release / self.rel; body = path.read_bytes(); path.unlink()
        self.put(self.base / 'alias', body); path.symlink_to(self.base / 'alias'); self.reject_prepare()

    def test_exact_destination_wrong_body_refuses(self):
        self.install_file(self.rel); self.path.write_bytes(b'FOREIGN_SENTINEL'); self.reject_prepare()
        self.assertEqual(self.path.read_bytes(), b'FOREIGN_SENTINEL')

    def test_exact_destination_wrong_gid_refuses(self):
        self.install_file(self.rel); self.set_owner(self.path, self.actor_app['uid'], 9999); self.reject_prepare()

    def test_exact_destination_wrong_uid_refuses(self):
        self.install_file(self.rel); self.set_owner(self.path, 0, 0); self.reject_prepare()

    def test_exact_destination_wrong_mode_refuses(self):
        self.install_file(self.rel); self.path.chmod(0o600); self.reject_prepare()

    def test_exact_destination_symlink_refuses(self):
        self.path.symlink_to(self.release / self.rel); self.reject_prepare()

    def test_exact_destination_hardlink_refuses(self):
        self.install_file(self.rel); os.link(self.path, self.base / 'retained-link'); self.reject_prepare()

    def test_exact_destination_acl_refuses(self):
        self.install_file(self.rel); self.acls[self.key(self.path)] = (b'foreign', b''); self.reject_prepare()

    def test_parent_group_writer_refuses(self):
        self.path.parent.chmod(0o775); self.reject_prepare()

    def test_home_not_private_refuses(self):
        home = self.host / 'home' / self.actor_app['user']; home.chmod(0o755); self.reject_prepare()

    def test_exact_config_parent_750_and_700_allowed_unchanged(self):
        self.path.parent.chmod(0o750)
        before = p.identity(self.path.parent.stat()); self.run_files()
        after = p.identity(self.path.parent.stat())
        self.assertEqual(before[:6], after[:6])
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o750)

    def test_parent_default_acl_refuses(self):
        self.acls[self.key(self.path.parent)] = (b'', b'inherited'); self.reject_prepare()

    def test_parent_swap_after_prepare_refuses(self):
        self.prepare_files(); self.publish_files()
        parent = self.path.parent; parent.rename(parent.with_name('retained'))
        self.mkdir(parent); self.set_owner(parent, self.actor_app['uid'], self.accounts[self.actor_app['user']].pw_gid)
        self.reject_apply()

    def test_missing_parent_not_created_or_adopted(self):
        self.path.parent.rmdir(); self.reject_prepare(); self.assertFalse(self.path.parent.exists())

    def test_foreign_exact_destination_appears_after_prepare(self):
        self.prepare_files(); self.publish_files(); self.put(self.path, b'FOREIGN')
        self.reject_apply(); self.assertEqual(self.path.read_bytes(), b'FOREIGN')

    def test_source_mount_identity_change_refuses(self):
        self.prepare_files(); self.publish_files()
        with patch.object(p, 'mount_id', return_value=92): self.reject_apply()

    def test_actor_identity_changed_refuses(self):
        self.prepare_files(); self.publish_files(); self.accounts[self.actor_app['user']].pw_gid += 1; self.reject_apply()

    def test_range_changed_refuses(self):
        self.prepare_files(); self.publish_files()
        with patch.object(m.storage, 'namespace_root_id', return_value=99999999): self.reject_apply()

    def test_lock_loss_refuses(self):
        self.prepare_files(); self.publish_files()
        with patch.object(m.o, 'lock_held', side_effect=ValueError('no canonical FD9')): self.reject_apply()

    def test_stopped_gate_refusal_preserves_inert_stages(self):
        self.prepare_files(); self.publish_files()
        original = m.stopped; calls = 0
        def gate(release, plan):
            nonlocal calls
            calls += 1
            if calls >= 2: raise ValueError('stopped gate changed')
            return original(release, plan)
        with patch.object(m, 'stopped', side_effect=gate): self.reject_apply()
        stages = list(self.host.rglob('.native-unit-files-*'))
        self.assertTrue(stages); self.assertFalse(self.path.exists())
        self.assertEqual((self.install / '.install-intent.json').read_bytes(), p.encoded(self.new_intent))

    def test_current_pointer_changed_refuses(self):
        self.prepare_files(); self.publish_files(); (self.install / 'current').symlink_to(self.release); self.reject_apply()

    def test_previous_cannot_be_supplied_without_current(self):
        self.prior['previousRelease'] = str(self.install / 'releases/unselected'); self.write_records(self.prior); self.reject_prepare()

    def test_previous_escape_and_foreign_current_refuse(self):
        (self.install / 'current').symlink_to(self.base); self.reject_prepare()

    def test_previous_source_changed_after_prepare(self):
        previous = self.previous_source(); self.prepare_files(); self.publish_files()
        target = previous / self.rel; target.write_bytes(target.read_bytes() + b'# changed\n'); self.reject_apply()

    def test_previous_private_receipt_required(self):
        previous = self.previous_source(); (previous / 'installation-receipt.json').chmod(0o644); self.reject_prepare()

    def test_previous_same_scope_provenance_required(self):
        previous = self.previous_source()
        metadata = copy.deepcopy(self.metadata); metadata['storageScope']['root'] = str(self.base / 'other')
        self.put(previous / 'podman-domains.json', p.encoded(metadata))
        value = p.strict((previous / 'installation-receipt.json').read_bytes()); value['inputs'] = self.fingerprint(previous)
        self.put(previous / 'installation-receipt.json', p.encoded(value)); self.reject_prepare()

    def test_direct_unit_override_refuses(self):
        self.put(self.host / 'home' / self.actor_app['user'] / '.config/systemd/user/webservices-webapp.service', b'foreign')
        self.reject_prepare()

    def test_target_runtime_env_dropin_is_explicit_noninventory_dependency(self):
        path = self.host / 'etc/systemd/system/webservices.target.d/10-runtime-env.conf'
        self.put(path, b'[Unit]\nRequires=webservices-runtime-env.service\n'); self.reject_prepare()
        self.assertTrue(path.exists())

    def test_quadlet_dropin_collision_refuses(self):
        self.mkdir(self.path.with_name(self.path.name + '.d')); self.reject_prepare()

    def test_generic_and_dash_unit_dropins_refuse(self):
        for name in ('service.d', 'webservices-.service.d'):
            path = self.host / 'etc/systemd/system' / name; self.mkdir(path)
            self.reject_prepare(); path.rmdir()

    def test_new_override_after_prepare_refuses(self):
        self.prepare_files(); self.publish_files(); self.mkdir(self.host / 'etc/systemd/system/service.d'); self.reject_apply()

    def test_missing_empty_domain_projection_refuses(self):
        self.prior['domainRuntimeProjections'].pop('finance'); self.write_records(self.prior); self.reject_prepare()

    def test_forged_completed_empty_domain_env_refuses(self):
        self.prior['domainRuntimeProjections']['finance']['environmentStoreHandoff'] = {'status': 'completed'}
        self.write_records(self.prior); self.reject_prepare()

    def test_destination_no_replace_race_preserves_foreign(self):
        self.prepare_files(); self.publish_files(); original = m.rename; raced = False
        def rename(parent, source, destination, exchange=False):
            nonlocal raced
            if not raced and destination == 'webservices-webapp.container':
                raced = True; self.put(self.path, b'FOREIGN_RACE')
            return original(parent, source, destination, exchange)
        with patch.object(m, 'rename', side_effect=rename): self.reject_apply()
        self.assertEqual(self.path.read_bytes(), b'FOREIGN_RACE')
        self.assertTrue(list(self.path.parent.glob('.native-unit-files-*')))

    def test_exchange_race_restores_foreign_without_read_or_delete(self):
        previous = self.previous_source(); self.install_file(self.rel, previous)
        self.prepare_files(); self.publish_files(); original = m.rename; raced = False
        def rename(parent, source, destination, exchange=False):
            nonlocal raced
            if not raced and destination == self.path.name and exchange:
                raced = True; self.path.rename(self.path.with_name('retained-selected-old'))
                self.put(self.path, b'FOREIGN_RACE')
            return original(parent, source, destination, exchange)
        with patch.object(m, 'rename', side_effect=rename): self.reject_apply()
        self.assertEqual(self.path.read_bytes(), b'FOREIGN_RACE')
        self.assertTrue(list(self.path.parent.glob('.native-unit-files-*')))

    def test_previous_only_removal_race_restores_foreign_without_overwrite(self):
        previous = self.previous_source(); rel = 'quadlet/rootful/webservices-oldonly.container'
        path = self.install_file(rel, previous)
        self.prepare_files(); self.publish_files(); original = m.rename; raced = False
        def rename(parent, source, destination, exchange=False):
            nonlocal raced
            if not raced and source == path.name:
                raced = True; path.rename(path.with_name('retained-selected-old')); self.put(path, b'FOREIGN_RACE')
            return original(parent, source, destination, exchange)
        with patch.object(m, 'rename', side_effect=rename): self.reject_apply()
        self.assertEqual(path.read_bytes(), b'FOREIGN_RACE')


class StoppedGate(unittest.TestCase):
    def setUp(self):
        self.entry = dict(uid=0, user='root', files={
            'quadlet/rootful/webservices-edge.container': dict(unit='webservices-edge.service'),
            'quadlet/rootful/webservices.target': dict(unit='webservices.target')},
            units=['webservices-edge.service', 'webservices.target'])
        self.plan = dict(scopes={'rootful': self.entry}, sources={'candidate': dict(scopes={'rootful': self.entry})})
        self.release = Path('/var/lib/stack-model/releases/candidate')
        self.props = [dict(Id=unit, Names=unit, LoadState='not-found', ActiveState='inactive',
            MainPID='0', Job='', DropInPaths='', SourcePath='', FragmentPath='') for unit in self.entry['units']]
        self.jobs = ''
        self.inactive = patch.object(m.o, 'inactive').start(); self.addCleanup(patch.stopall)
        def query(command, **kwargs):
            self.assertEqual(command[0], 'systemctl')
            self.assertIn(command[1], ('show', 'list-jobs'))
            if command[1] == 'show':
                self.assertEqual(command[2:4], self.entry['units'])
                body = '\n\n'.join('\n'.join(key + '=' + value for key, value in props.items()) for props in self.props)
            else: body = self.jobs
            return SimpleNamespace(returncode=0, stdout=body)
        patch.object(subprocess, 'run', side_effect=query).start()

    def test_exact_rootful_not_found_and_all_seven_stopped_actor_gates(self):
        m.stopped(self.release, self.plan)
        self.assertEqual({call.args[1] for call in self.inactive.call_args_list}, set(n.IDENTITIES))

    def test_loaded_exact_generated_and_target_sources(self):
        for props in self.props: props['LoadState'] = 'loaded'
        self.props[0].update(SourcePath='/etc/containers/systemd/webservices-edge.container',
                             FragmentPath='/run/systemd/generator/webservices-edge.service')
        self.props[1]['FragmentPath'] = '/etc/systemd/system/webservices.target'
        m.stopped(self.release, self.plan)

    def test_active_job_alias_dropin_source_and_pid_refuse(self):
        for key, value in (('ActiveState', 'active'), ('Job', '23'), ('Names', 'webservices-edge.service foreign.service'),
                           ('MainPID', '7'), ('DropInPaths', '/etc/systemd/system/foreign.conf')):
            original = self.props[0][key]; self.props[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): m.stopped(self.release, self.plan)
            self.props[0][key] = original
        self.props[0].update(LoadState='loaded', SourcePath='/foreign', FragmentPath='/foreign')
        with self.assertRaises(ValueError): m.stopped(self.release, self.plan)

    def test_selected_rootful_job_refuses_but_foreign_job_not_selected(self):
        self.jobs = '17 foreign.service start running\n'; m.stopped(self.release, self.plan)
        self.jobs += '18 webservices-edge.service start waiting\n'
        with self.assertRaises(ValueError): m.stopped(self.release, self.plan)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--group', type=int, choices=range(1, 9), help='one of eight sequential <=120s groups')
    selection.add_argument('--match')
    args = parser.parse_args()
    # Inherit fixture utilities, never replay the earlier contributor's suite.
    tests = [(cls, name) for cls in (Files, StoppedGate) for name in cls.__dict__ if name.startswith('test_')]
    if args.group is not None:
        tests = [item for index, item in enumerate(tests) if index % 8 == args.group - 1]
    if args.match:
        tests = [item for item in tests if args.match in item[1]]
    if not tests: parser.error('no matching tests')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(cls(name) for cls, name in tests))
    raise SystemExit(not result.wasSuccessful())
