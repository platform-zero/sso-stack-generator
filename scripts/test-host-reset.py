#!/usr/bin/env python3
"""Unprivileged temp-root/mock proofs ONLY. Never invokes systemctl or reset on host.

Ownership is explicitly modeled as root for these fixtures; passing these tests
is not native installed/production/service acceptance. No sudo or packages.
"""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / 'runtime-generator/podman-ops/host-reset.py'
spec = importlib.util.spec_from_file_location('host_reset_test_subject', SOURCE)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
REAL_STAT = os.stat
REAL_FSTAT = os.fstat
REAL_EUID = os.geteuid()
REAL_JOURNAL_OFFLINE = m.journal_offline
REAL_ACCESS_ACL = m.access_acl


class StatView:
    def __init__(self, original, uid, trusted_ancestor=False, gid=None):
        self.original, self.st_uid = original, uid
        self.st_gid = gid if gid is not None else (0 if original.st_gid == os.getgid() else original.st_gid)
        # Model root-controlled production ancestors, never chmod the checkout.
        self.st_mode = original.st_mode & ~0o022 if trusted_ancestor else original.st_mode
    def __getattr__(self, name): return getattr(self.original, name)


class Reset(unittest.TestCase):
    def setUp(self):
        # Stay inside the owning checkout; never inspect another stream's files.
        self.tmp = tempfile.TemporaryDirectory(prefix='.host-reset-test-', dir=REPO)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'metadata'; self.root.mkdir(mode=0o700)
        self.scope = self.base / 'scope'; self.scope.mkdir(mode=0o700)
        self.release = self.root / 'releases/r1'; self.release.mkdir(parents=True, mode=0o700)
        (self.release / 'site').mkdir(mode=0o700)
        (self.root / '.install.lock').touch(mode=0o600)
        self.row = {'name': 'fixture', 'user': 'fixture-app', 'uid': 210001,
                    'stateRoot': str(self.scope / 'state/fixture'),
                    'graphRoot': str(self.scope / 'graphs/fixture'),
                    'volumeRoot': str(self.scope / 'volumes/fixture')}
        for key in ('stateRoot', 'graphRoot', 'volumeRoot'):
            Path(self.row[key]).mkdir(parents=True, mode=0o700)
        self.app = Path(self.row['volumeRoot']) / 'database'; self.app.mkdir(mode=0o700)
        self.populate()
        self.cache = Path(self.row['graphRoot']) / 'unrelated-cache'
        self.cache.write_text('synthetic cache must survive')
        self.failed = Path(self.row['stateRoot']) / 'failed-evidence.json'
        self.failed.write_text('{"syntheticEvidence":true}')
        self.sibling = self.scope / 'unselected'; self.sibling.mkdir(mode=0o700)
        (self.sibling / 'keep').write_text('synthetic unrelated data')
        self.manifest = {'site': 'fixture', 'deploymentMode': 'standalone',
                         'installerStateRoot': str(self.root),
                         'storageScope': {'root': str(self.scope), 'dataClass': 'synthetic'}}
        self.metadata = {'schemaVersion': 1, 'deploymentMode': 'standalone',
                         'installerStateRoot': str(self.root), 'storageScope': self.manifest['storageScope'],
                         'domains': [self.row]}
        self.ir = {'volumes': {'database': {'hostPath': str(self.app)}},
                   'services': {'db': {'volumes': ['database:/data']}}}
        for label in ('rootful', 'rootless-fixture'):
            units = self.release / 'quadlet' / label; units.mkdir(parents=True)
            (units / 'webservices.target').write_text('[Unit]\nDescription=Synthetic test\n')
            (units / 'webservices-db.container').write_text('[Container]\nImage=synthetic-invalid\n')
        self.seal()
        (self.root / 'current').symlink_to(self.release)
        self.uid_overrides = {}; self.gid_overrides = {}; self.acl_overrides = {}
        ancestors = {(REAL_STAT(p).st_dev, REAL_STAT(p).st_ino) for p in self.base.parents}
        def model(info):
            key = (info.st_dev, info.st_ino)
            uid = self.uid_overrides.get(key, 0 if info.st_uid == REAL_EUID else info.st_uid)
            return StatView(info, uid, key in ancestors, self.gid_overrides.get(key))
        self.patch(m.os, 'stat', side_effect=lambda *a, **k: model(REAL_STAT(*a, **k)))
        self.patch(m.os, 'fstat', side_effect=lambda *a, **k: model(REAL_FSTAT(*a, **k)))
        self.patch(m.os, 'geteuid', return_value=0)
        self.patch(pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=self.row['uid'], pw_gid=self.row['uid'], pw_dir='/home/fixture-app'))
        self.patch(m, 'read_allocation_files', side_effect=self.allocation_files)
        self.patch(m, 'identity_ids', return_value=[0, 1000, self.row['uid']])
        self.patch(m, 'access_acl', side_effect=lambda fd: self.acl_overrides.get(
            (REAL_FSTAT(fd).st_dev, REAL_FSTAT(fd).st_ino), []))
        self.patch(m.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=2000))
        self.offline = self.patch(m, 'journal_offline', return_value=False)
        self.patch(m, 'mount_views', side_effect=self.safe_mounts)
        # Never read installed package sources on the development host.
        self.patch(m, 'native_podman_source', return_value=None)
        real_directory = m.directory
        @contextlib.contextmanager
        def fixture_directory(value):
            value = Path(value)
            if not any(value.is_relative_to('/home/' + d['user']) for d in self.metadata['domains']):
                with real_directory(value) as fd: yield fd
                return
            # Virtualize the entire /home chain. NEVER inspect real host homes.
            homes = self.base / 'homes'
            if not homes.exists(): raise FileNotFoundError('mock absent configuration')
            fd = os.open(homes, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                logical = Path('/home')
                for part in value.relative_to('/home').parts:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd); fd = child; logical /= part
                    m.directory_authority(fd, logical)
                yield fd
            finally: os.close(fd)
        self.patch(m, 'directory', side_effect=fixture_directory)
        self.calls = []
        self.patch(m, 'run_read', side_effect=self.unit_read)
        self.patch(m.subprocess, 'run', side_effect=AssertionError('native process execution forbidden in fixture'))
        self.original_journal = (self.root / '.install-intent.json').read_bytes()
        # Every negative case begins from a proven, usable mocked baseline.
        self.reviewed()
        self.calls.clear()

    def patch(self, obj, name, **kwargs):
        p = patch.object(obj, name, **kwargs); result = p.start(); self.addCleanup(p.stop); return result

    def populate(self):
        (self.app / 'rows').mkdir(mode=0o700)
        (self.app / 'rows/data.json').write_text('{"synthetic":true,"rows":[1,2,3]}')
        (self.app / 'index').write_bytes(b'synthetic-index\n')

    def save(self, destination, value, private=False):
        raw = m.canonical(value); destination.write_bytes(raw)
        destination.chmod(0o600 if private else 0o644)
        return hashlib.sha256(raw).hexdigest()

    def seal(self, phase='active'):
        pins = {}
        pins['site/manifest.json'] = self.save(self.release / 'site/manifest.json', self.manifest)
        pins['podman-domains.json'] = self.save(self.release / 'podman-domains.json', self.metadata)
        pins['stack.ir.json'] = self.save(self.release / 'stack.ir.json', self.ir)
        pins['source-provenance.json'] = self.save(self.release / 'source-provenance.json',
                                                  {'manifestSha256': pins['site/manifest.json']})
        pins['bundle.json'] = self.save(self.release / 'bundle.json',
                                       {'backend': 'podman', 'irSha256': pins['stack.ir.json'],
                                        'sourceProvenanceSha256': pins['source-provenance.json']})
        receipt = {'schemaVersion': 1, 'phase': phase, 'inputs': pins, 'release': str(self.release),
                   'steps': ['preparing', phase]}
        self.intent = self.save(self.root / '.install-intent.json', receipt, True)
        self.save(self.release / 'installation-receipt.json', receipt, True)
        marker = {'schemaVersion': 1, 'kind': 'standalone-stack-storage', 'site': self.manifest['site'],
                  'scope': self.manifest['storageScope'],
                  'domains': [{k: d[k] for k in ('name', 'user', 'uid', 'stateRoot', 'graphRoot', 'volumeRoot')}
                              for d in sorted(self.metadata['domains'], key=lambda d: d['name'])],
                  'roots': sorted(d[k] for d in self.metadata['domains'] for k in ('stateRoot', 'graphRoot', 'volumeRoot'))}
        self.save(self.scope / m.MARKER, marker, True)

    def allocation_files(self):
        raw = ''.join(d['user'] + ':' + str(2000000 + i * 65536) + ':65536\n'
                      for i, d in enumerate(self.metadata['domains'])).encode()
        return {'subuid': raw, 'subgid': raw}

    def safe_mounts(self):
        dev = REAL_STAT(self.app).st_dev
        device = str(os.major(dev)) + ':' + str(os.minor(dev))
        rows = [f'1 0 {device} / / rw - synthetic synthetic rw']
        return [rows, rows]

    def unit_read(self, command):
        self.calls.append(command)
        if 'list-jobs' in command: return SimpleNamespace(returncode=0, stdout='')
        unit = command[command.index('show') + 1]
        props = {'Id': unit, 'LoadState': 'not-found', 'ActiveState': 'inactive', 'SubState': 'dead',
                 'UnitFileState': '', 'FragmentPath': '', 'SourcePath': '', 'Job': '',
                 'TriggeredBy': '', 'Triggers': '', 'Names': unit, 'DropInPaths': '',
                 'NeedDaemonReload': 'no', 'Transient': 'no'}
        return SimpleNamespace(returncode=0, stdout=''.join(k + '=' + v + '\n' for k, v in props.items()))

    def reviewed(self): return m.review(self.root, self.intent)

    def execute(self, reviewed=None):
        reviewed = reviewed or self.reviewed()
        return m.reset(self.root, self.intent, reviewed['planSha256'])

    def denied(self, action=None):
        before = (self.app / 'index').read_bytes()
        with self.assertRaises((ValueError, OSError, KeyError, json.JSONDecodeError)):
            (action or self.reviewed)()
        self.assertEqual((self.app / 'index').read_bytes(), before)

    def foreign(self, item, uid=987654):
        info = REAL_STAT(item, follow_symlinks=False)
        self.uid_overrides[(info.st_dev, info.st_ino)] = uid

    def owned(self, item, uid, gid=None):
        self.foreign(item, uid)
        info = REAL_STAT(item, follow_symlinks=False)
        self.gid_overrides[(info.st_dev, info.st_ino)] = uid if gid is None else gid

    def lab_model(self):
        """Seven fresh synthetic actors, operator scope and exact execute ACLs.

        All ownership/account/ACL/process/systemd facts are MODELED, not native.
        No chown, host scope/account read or privileged service call occurs.
        """
        self.row['uid'] = 780
        rows = [self.row]
        for i in range(1, 7):
            name = 'lab' + str(i); user = 'fixture-' + name
            row = {'name': name, 'user': user, 'uid': 780 + i}
            for key, parent in (('stateRoot', 'state'), ('graphRoot', 'graphs'), ('volumeRoot', 'volumes')):
                p = self.scope / parent / name; p.mkdir(mode=0o700)
                row[key] = str(p)
            units = self.release / 'quadlet' / ('rootless-' + name); units.mkdir(mode=0o700)
            (units / 'webservices.target').write_text('[Unit]\nDescription=Synthetic lab\n')
            (units / 'webservices-db.container').write_text('[Container]\nImage=synthetic-invalid\n')
            rows.append(row)
        self.metadata['domains'] = rows
        self.scope.chmod(0o2770); self.owned(self.scope, 1000, 2000)
        acl = [[1, 7, 2**32 - 1], [4, 7, 2**32 - 1], [16, 7, 2**32 - 1], [32, 0, 2**32 - 1]]
        acl += [[2, 1, d['uid']] for d in rows]
        self.acl_overrides[(REAL_STAT(self.scope).st_dev, REAL_STAT(self.scope).st_ino)] = sorted(acl)
        for row in rows:
            for key in ('stateRoot', 'graphRoot', 'volumeRoot'):
                self.owned(Path(row[key]), row['uid'])
        accounts = {r['user']: SimpleNamespace(pw_uid=r['uid'], pw_gid=r['uid'], pw_dir='/home/' + r['user']) for r in rows}
        self.patch(pwd, 'getpwnam', side_effect=accounts.__getitem__)
        self.owned(self.app, 780)
        self.owned(self.app / 'index', 2000000 + 999)
        self.owned(self.app / 'rows', 2000000)
        self.owned(self.app / 'rows/data.json', 2000000 + 999)
        source = self.scope / 'global/database'  # deliberately NOT the live private volume
        self.ir['volumes']['database'] = {'hostPath': str(source), 'rootlessStrategy': 'copy'}
        self.ir['services'] = {'db': {'placement': 'rootless', 'rootlessDomain': self.row['name'],
                                      'volumes': ['database:/data']}}
        self.offline.return_value = True
        self.seal('retired-failed')
        return rows

    def offline_read(self, command):
        if 'is-enabled' in command:
            self.calls.append(command)
            self.assertIn('SYSTEMD_OFFLINE=1', command)
            units = command[command.index('is-enabled') + 1:]
            return SimpleNamespace(returncode=1, stdout='disabled\n' * len(units))
        self.assertNotIn('--user', command, 'stopped manager must not be contacted')
        return self.unit_read(command)

    def test_exact_reset_preserves_top_roots_receipts_journals_and_unrelated_data(self):
        reviewed = self.reviewed()
        inode = REAL_STAT(self.app).st_ino
        marker = (self.scope / m.MARKER).read_bytes()
        result = self.execute(reviewed)
        self.assertEqual(result['phase'], 'empty-owned-app-data')
        self.assertEqual(result['emptied'], [str(self.app)])
        self.assertEqual(list(self.app.iterdir()), [])
        self.assertEqual(REAL_STAT(self.app).st_ino, inode)
        self.assertEqual((self.scope / m.MARKER).read_bytes(), marker)
        self.assertEqual((self.root / '.install-intent.json').read_bytes(), self.original_journal)
        self.assertEqual((self.release / 'installation-receipt.json').read_bytes(), self.original_journal)
        self.assertTrue(self.cache.exists()); self.assertTrue(self.failed.exists())
        self.assertEqual((self.sibling / 'keep').read_text(), 'synthetic unrelated data')
        evidence = list((self.root / '.host-reset').iterdir())
        self.assertEqual(len(evidence), 3)
        for item in evidence:
            self.assertEqual(stat.S_IMODE(REAL_STAT(item).st_mode), 0o600)
        self.assertNotIn('synthetic-index', ''.join(p.read_text() for p in evidence))
        self.assertTrue(self.calls)
        self.assertTrue(all('show' in c or 'list-jobs' in c for c in self.calls))

    def test_nonroot_execution_refused(self):
        with patch.object(m.os, 'geteuid', return_value=1000): self.denied()

    def test_production_even_with_matching_marker_is_refused(self):
        self.manifest['storageScope']['dataClass'] = 'production'; self.seal(); self.denied()

    def test_managed_and_guest_venue_authority_refused(self):
        for change in ('managed', 'venue', 'agentVmSpec'):
            with self.subTest(change=change):
                if change == 'managed': self.manifest['deploymentMode'] = 'managed'
                elif change == 'venue': self.metadata['venue'] = {}
                else: self.manifest['agentVmSpec'] = 'synthetic.json'
                self.seal(); self.denied()
                self.manifest['deploymentMode'] = 'standalone'
                self.metadata.pop('venue', None); self.manifest.pop('agentVmSpec', None)

    def test_unmarked_and_mismatched_scope_refused(self):
        (self.scope / m.MARKER).unlink(); self.denied()
        self.seal()
        value = m.strict((self.scope / m.MARKER).read_bytes()); value['site'] = 'foreign'
        self.save(self.scope / m.MARKER, value, True); self.denied()

    def test_linked_marker_and_hardlinked_receipt_refused(self):
        item = self.scope / m.MARKER; original = self.base / 'marker-copy'
        item.rename(original); item.symlink_to(original); self.denied()
        item.unlink(); original.rename(item)
        os.link(self.release / 'installation-receipt.json', self.base / 'receipt-alias')
        self.denied()

    def test_insecure_marker_or_journal_permissions_refused(self):
        for item in (self.scope / m.MARKER, self.root / '.install-intent.json'):
            with self.subTest(item=item.name):
                item.chmod(0o644); self.denied(); item.chmod(0o600)

    def test_foreign_scope_root_and_contents_refused(self):
        for item in (self.scope, self.app, self.app / 'index'):
            with self.subTest(item=item.name):
                self.foreign(item); self.denied(); self.uid_overrides.clear()

    def test_selected_service_uid_allowed_only_beneath_selected_volume_parent(self):
        self.foreign(self.app / 'index', self.row['uid'])
        self.assertEqual(self.execute()['phase'], 'empty-owned-app-data')

    def test_unrelated_mapped_uid_is_not_adopted(self):
        self.foreign(self.app / 'index', 3000000); self.denied()

    def test_group_or_world_writable_root_or_children_refused(self):
        for item in (self.app, self.app / 'rows', self.app / 'index'):
            before = stat.S_IMODE(REAL_STAT(item).st_mode)
            for bits in (0o020, 0o002):
                with self.subTest(item=item.name, bits=bits):
                    item.chmod(before | bits); self.denied(); item.chmod(before)

    def test_symlink_hardlink_fifo_and_linked_ancestor_refused(self):
        bad = self.app / 'bad'
        os.link(self.cache, bad); self.denied(); bad.unlink()
        os.mkfifo(bad); self.denied(); bad.unlink()
        moved = self.app.with_name('moved'); self.app.rename(moved); self.app.symlink_to(moved)
        self.denied(); self.app.unlink(); moved.rename(self.app)

    def test_journal_evidence_inside_app_data_refused(self):
        (self.app / 'installation-receipt.json').write_text('{}'); self.denied()

    def test_exact_pointer_required_and_other_symlinks_refused(self):
        pointer = self.root / 'current'; pointer.unlink(); self.denied()
        pointer.symlink_to('releases/r1'); self.denied()
        pointer.unlink(); pointer.symlink_to(self.release)
        self.foreign(pointer); self.denied()

    def test_journal_receipt_hash_and_input_provenance_mismatch_refused(self):
        self.denied(lambda: m.review(self.root, '0' * 64))
        (self.release / 'installation-receipt.json').write_text('{}'); self.denied(); self.seal()
        (self.release / 'stack.ir.json').write_text('{"tampered":true}'); self.denied(); self.seal()
        # Even newly hashed inconsistent provenance is rejected.
        receipt = m.strict((self.root / '.install-intent.json').read_bytes())
        receipt['inputs']['source-provenance.json'] = self.save(self.release / 'source-provenance.json',
                                                               {'manifestSha256': '0' * 64})
        self.intent = self.save(self.root / '.install-intent.json', receipt, True)
        self.save(self.release / 'installation-receipt.json', receipt, True); self.denied()

    def test_duplicate_json_and_nonfinite_values_refused(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'[]'):
            with self.assertRaises(m.Refusal): m.strict(raw)

    def test_incomplete_or_unrecognized_input_receipt_refused(self):
        for mutation in ('missing', 'extra', 'null'):
            self.seal(); value = m.strict((self.root / '.install-intent.json').read_bytes())
            if mutation == 'missing': value['inputs'].pop('podman-domains.json')
            elif mutation == 'extra': value['inputs']['../../foreign'] = '0' * 64
            else: value['inputs']['stack.ir.json'] = None
            self.intent = self.save(self.root / '.install-intent.json', value, True)
            self.save(self.release / 'installation-receipt.json', value, True); self.denied()

    def test_nonterminal_installation_cannot_reset(self):
        for phase in ('preparing', 'units-selected', 'building', 'starting'):
            with self.subTest(phase=phase): self.seal(phase); self.denied()

    def test_failed_selected_installation_keeps_failure_receipts(self):
        self.seal('failed'); before = (self.root / '.install-intent.json').read_bytes()
        self.execute()
        self.assertEqual((self.root / '.install-intent.json').read_bytes(), before)
        self.assertEqual((self.release / 'installation-receipt.json').read_bytes(), before)

    def test_scope_escape_state_cache_parent_and_overlap_refused(self):
        targets = (self.sibling.parent.parent, self.scope, Path(self.row['graphRoot']),
                   Path(self.row['stateRoot']), Path(self.row['volumeRoot']))
        for target in targets:
            with self.subTest(target=target.name):
                self.ir['volumes']['database']['hostPath'] = str(target); self.seal(); self.denied()
        self.ir['volumes']['database']['hostPath'] = str(self.app)
        self.ir['volumes']['duplicate'] = {'hostPath': str(self.app / 'rows')}
        self.ir['services']['db']['volumes'].append('duplicate:/other'); self.seal(); self.denied()

    def test_unmapped_named_volume_refused(self):
        self.ir['volumes']['unmapped'] = {}; self.seal(); self.denied()

    def test_canonical_path_checks(self):
        for value in ('/', 'relative', '/a/../b', '/a/./b', '/a//b', '/a/', None):
            with self.subTest(value=value), self.assertRaises(m.Refusal): m.path(value)

    def test_native_inactive_proof_fails_on_active_enabled_queued_or_foreign_triggers(self):
        cases = [('ActiveState', 'active'), ('ActiveState', 'failed'), ('SubState', 'running'),
                 ('Job', '23'), ('TriggeredBy', 'foreign.socket'), ('Triggers', 'foreign.service'),
                 ('Names', 'webservices-db.service alias.service'), ('Id', 'foreign.service'),
                 ('LoadState', 'error'), ('FragmentPath', '/foreign.service'), ('UnitFileState', 'enabled'),
                 ('DropInPaths', '/foreign.conf'), ('NeedDaemonReload', 'yes'), ('Transient', 'yes')]
        for key, value in cases:
            def altered(command):
                result = self.unit_read(command)
                if 'show' in command:
                    lines = result.stdout.splitlines()
                    result.stdout = '\n'.join(k + '=' + (value if k == key else v)
                                              for k, v in (s.split('=', 1) for s in lines)) + '\n'
                return result
            with self.subTest(key=key, value=value), patch.object(m, 'run_read', side_effect=altered):
                self.denied()

    def test_missing_duplicate_or_failed_unit_response_refused(self):
        for mode in ('missing', 'duplicate', 'failed'):
            def bad(command):
                result = self.unit_read(command)
                if 'show' in command:
                    if mode == 'missing': result.stdout = result.stdout.replace('Job=\n', '')
                    elif mode == 'duplicate': result.stdout += 'Job=\n'
                    else: result.returncode = 1
                return result
            with self.subTest(mode=mode), patch.object(m, 'run_read', side_effect=bad): self.denied()

    def test_any_manager_jobs_refused_without_cancelling_them(self):
        def jobs(command):
            if 'list-jobs' in command: return SimpleNamespace(returncode=0, stdout='1 unrelated.service start running\n')
            return self.unit_read(command)
        with patch.object(m, 'run_read', side_effect=jobs): self.denied()
        self.assertFalse(any('cancel' in call for call in self.calls))

    def test_selected_timers_and_sockets_are_inventoried(self):
        units = self.release / 'quadlet/rootful'
        for name in ('webservices-periodic.timer', 'webservices-api.socket'):
            (units / name).write_text('[Unit]\nDescription=Synthetic\n')
        proof = self.reviewed()['plan']['managers'][0]['units']
        self.assertIn('webservices-periodic.timer', proof)
        self.assertIn('webservices-api.socket', proof)
        self.assertIn('webservices-auto-update.timer', proof)
        rootless = self.reviewed()['plan']['managers'][1]['units']
        self.assertIn('podman.socket', rootless)
        self.assertIn('podman.service', rootless)

    def test_unclassified_or_foreign_selected_source_refused(self):
        source = self.release / 'quadlet/rootful/foreign.container'; source.write_text('synthetic')
        self.denied(); source.unlink()
        source = self.release / 'quadlet/rootful/webservices-unknown.conf'; source.write_text('synthetic')
        self.denied()

    def test_account_drift_refused(self):
        with patch.object(pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=44, pw_gid=44, pw_dir='/home/fixture-app')):
            self.denied()

    def test_selected_and_nested_mounts_refused_including_other_namespaces(self):
        for mode in ('root', 'child', 'alias', 'parent-alias'):
            views = self.safe_mounts(); device = views[0][0].split()[2]
            if mode in ('root', 'child'):
                mountpoint = self.app if mode == 'root' else self.app / 'rows'
                views[0] = views[0] + [f'2 1 {device} / {mountpoint} rw - synthetic synthetic rw']
            else:
                mountroot = self.app if mode == 'alias' else self.app.parent
                views[1] = views[1] + [f'2 1 {device} {mountroot} /alias rw - synthetic synthetic rw']
            with self.subTest(mode=mode), patch.object(m, 'mount_views', return_value=views): self.denied()

    def test_unavailable_or_malformed_mount_proof_refused(self):
        for views in ([], [[]], [['malformed']]):
            with self.subTest(views=views), patch.object(m, 'mount_views', return_value=views):
                # Empty views must refuse, not raise an unrelated IndexError.
                self.denied()
        with patch.object(m, 'mount_views', side_effect=PermissionError('mock unavailable namespace')):
            self.denied()

    def test_stale_plan_data_inode_marker_and_unit_hash_refused(self):
        for kind in ('content', 'inode', 'marker', 'unit'):
            reviewed = self.reviewed()
            with self.subTest(kind=kind):
                if kind == 'content': (self.app / 'index').write_bytes(b'changed synthetic content')
                elif kind == 'inode':
                    content = (self.app / 'index').read_bytes(); (self.app / 'index').unlink()
                    (self.app / 'index').write_bytes(content)
                elif kind == 'marker':
                    item = self.scope / m.MARKER; item.write_bytes(item.read_bytes() + b'\n')
                else: (self.release / 'quadlet/rootful/webservices.target').write_text('[Unit]\nDescription=Changed\n')
                self.denied(lambda: self.execute(reviewed))
        self.assertFalse((self.root / '.host-reset').exists())

    def test_no_deletion_on_plan_or_journal_cas_failure(self):
        self.denied(lambda: m.reset(self.root, self.intent, '0' * 64))
        self.denied(lambda: m.reset(self.root, '0' * 64, '1' * 64))
        self.assertFalse((self.root / '.host-reset').exists())

    def test_existing_lock_required_link_and_lock_contention_refused(self):
        lock = self.root / '.install.lock'; lock.unlink(); self.denied()
        lock.symlink_to(self.app / 'index'); self.denied(); lock.unlink(); lock.touch(mode=0o600)
        with patch.object(m.fcntl, 'flock', side_effect=BlockingIOError('mock installer holds lock')):
            self.denied()

    def test_preexisting_evidence_is_never_overwritten_and_no_backup_is_created(self):
        evidence = self.root / '.host-reset'; evidence.mkdir(mode=0o700)
        old = evidence / 'failed-before.json'; old.write_text('{"phase":"failed"}'); old.chmod(0o600)
        before = old.read_bytes(); self.execute()
        self.assertEqual(old.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.base.iterdir()), ['metadata', 'scope'])

    def test_linked_or_insecure_evidence_directory_refused_before_delete(self):
        evidence = self.root / '.host-reset'; evidence.symlink_to(self.sibling)
        self.denied(lambda: self.execute()); evidence.unlink(); evidence.mkdir(mode=0o700); evidence.chmod(0o755)
        self.denied(lambda: self.execute())

    def test_failure_after_intent_is_retained_separately_and_new_review_can_retry(self):
        reviewed = self.reviewed()
        with patch.object(m, 'erase', side_effect=m.Refusal('mock destructive-stage failure')):
            self.denied(lambda: self.execute(reviewed))
        evidence = list((self.root / '.host-reset').iterdir())
        self.assertEqual(len(evidence), 2)
        failed = [m.strict(p.read_bytes()) for p in evidence if p.name.endswith('-result.json')][0]
        self.assertEqual(failed['phase'], 'failed-partial-no-automatic-retry')
        self.assertEqual((self.root / '.install-intent.json').read_bytes(), self.original_journal)
        self.execute(self.reviewed())
        self.assertTrue(all(p.exists() for p in evidence))

    def test_second_native_probe_blocks_reset_and_records_failure(self):
        reviewed = self.reviewed(); original = m.verify_inactive; calls = [0]
        def changed(managers):
            calls[0] += 1
            if calls[0] == 2: raise m.Refusal('mock unit restarted after plan')
            return original(managers)
        with patch.object(m, 'verify_inactive', side_effect=changed): self.denied(lambda: self.execute(reviewed))
        self.assertTrue(any((self.root / '.host-reset').glob('*-result.json')))

    def test_tree_bound_prevents_unbounded_inventory(self):
        with patch.object(m, 'MAX_NODES', 1): self.denied()

    def test_real_temp_lock_serializes_with_second_installer_lock_descriptor(self):
        with m.locked(self.root):
            self.denied()
        self.reviewed()

    def test_loaded_unit_requires_exact_owned_source_hash_and_disabled_triggers(self):
        source = self.base / 'webservices-example.service'; source.write_text('[Unit]\nDescription=Synthetic\n')
        authority = {'source': str(source), 'sha256': m.sha(source.read_bytes())}
        unit = 'webservices-example.service'
        managers = [{'manager': 'fixture', 'command': ['mock-only'], 'units': {unit: authority}}]
        def loaded(command):
            if 'list-jobs' in command: return SimpleNamespace(returncode=0, stdout='')
            props = {'Id': unit, 'Names': unit, 'LoadState': 'loaded', 'ActiveState': 'inactive',
                     'SubState': 'dead', 'UnitFileState': 'static', 'FragmentPath': str(source),
                     'SourcePath': '', 'Job': '', 'TriggeredBy': '', 'Triggers': '',
                     'DropInPaths': '', 'NeedDaemonReload': 'no', 'Transient': 'no'}
            return SimpleNamespace(returncode=0, stdout=''.join(k + '=' + v + '\n' for k, v in props.items()))
        with patch.object(m, 'run_read', side_effect=loaded):
            m.verify_inactive(managers)
            source.write_text('different synthetic unit')
            with self.assertRaises(m.Refusal): m.verify_inactive(managers)
        source.write_text('[Unit]\nDescription=Synthetic\n')
        for suffix in ('.timer', '.socket', '.target'):
            unit = 'webservices-example' + suffix
            managers[0]['units'] = {unit: authority}
            with self.subTest(suffix=suffix), patch.object(m, 'run_read', side_effect=loaded):
                with self.assertRaises(m.Refusal): m.verify_inactive(managers)

    def test_implicit_update_sources_are_pinned_from_selected_release_ops(self):
        ops = self.release / 'ops'; ops.mkdir(mode=0o700)
        for unit in ('webservices-auto-update.timer', 'webservices-auto-update.service'):
            (ops / unit).write_text('[Unit]\nDescription=Synthetic update\n')
        reviewed = self.reviewed()
        units = reviewed['plan']['managers'][0]['units']
        self.assertEqual(units['webservices-auto-update.timer']['source'],
                         '/etc/systemd/system/webservices-auto-update.timer')
        self.assertEqual(units['webservices-auto-update.timer']['sha256'],
                         m.sha((ops / 'webservices-auto-update.timer').read_bytes()))
        (ops / 'webservices-auto-update.timer').write_text('changed synthetic timer')
        self.denied(lambda: self.execute(reviewed))

    def test_selected_rootless_native_socket_must_be_inactive_and_fenced(self):
        for field, value in (('ActiveState', 'active'), ('UnitFileState', 'enabled'), ('Job', '42')):
            def unfenced(command):
                result = self.unit_read(command)
                if 'podman.socket' in command:
                    rows = [line.split('=', 1) for line in result.stdout.splitlines()]
                    result.stdout = ''.join(k + '=' + (value if k == field else v) + '\n' for k, v in rows)
                return result
            with self.subTest(field=field), patch.object(m, 'run_read', side_effect=unfenced): self.denied()

    def test_package_source_helper_hashes_only_exact_owned_fixture(self):
        source = self.base / 'podman.socket'; source.write_text('[Socket]\nListenStream=synthetic\n')
        self.assertEqual(m.source_authority(source, source),
                         {'source': str(source), 'sha256': m.sha(source.read_bytes())})
        self.foreign(source)
        with self.assertRaises(m.Refusal): m.source_authority(source, source)
        self.assertIsNone(m.source_authority(self.base / 'absent-source', source))

    def test_loaded_implicit_update_trigger_without_source_authority_refused(self):
        def loaded(command):
            result = self.unit_read(command)
            if 'webservices-auto-update.timer' in command:
                result.stdout = result.stdout.replace('LoadState=not-found', 'LoadState=loaded')
                result.stdout = result.stdout.replace('UnitFileState=\n', 'UnitFileState=disabled\n')
            return result
        with patch.object(m, 'run_read', side_effect=loaded): self.denied()

    def test_marker_whitespace_changed_after_intent_is_a_cas_failure(self):
        reviewed = self.reviewed(); original = m.write_evidence
        def change_after_intent(fd, filename, value):
            original(fd, filename, value)
            if filename.endswith('-intent.json'):
                marker = self.scope / m.MARKER; marker.write_bytes(marker.read_bytes() + b'\n')
        with patch.object(m, 'write_evidence', side_effect=change_after_intent):
            self.denied(lambda: self.execute(reviewed))
        self.assertTrue(any((self.root / '.host-reset').glob('*-result.json')))

    def test_partial_second_root_failure_keeps_progress_and_requires_fresh_plan(self):
        second = Path(self.row['volumeRoot']) / 'second'; second.mkdir(mode=0o700)
        (second / 'synthetic').write_text('synthetic second root')
        self.ir['volumes']['second'] = {'hostPath': str(second)}
        self.ir['services']['db']['volumes'].append('second:/other'); self.seal()
        reviewed = self.reviewed(); original = m.erase; calls = [0]
        def fail_second(fd, entries):
            calls[0] += 1
            # First root calls erase recursively for its rows directory, so
            # identify the second root from its exact one-file inventory.
            if [e['name'] for e in entries] == ['synthetic']:
                raise m.Refusal('mock second-root failure')
            return original(fd, entries)
        with patch.object(m, 'erase', side_effect=fail_second), self.assertRaises(m.Refusal):
            self.execute(reviewed)
        self.assertEqual(list(self.app.iterdir()), [])
        self.assertTrue((second / 'synthetic').exists())
        evidence = list((self.root / '.host-reset').iterdir())
        failed = [m.strict(p.read_bytes()) for p in evidence if p.name.endswith('-result.json')][0]
        self.assertEqual(failed['emptied'], [str(self.app)])
        self.assertEqual(failed['phase'], 'failed-partial-no-automatic-retry')
        with self.assertRaises(m.Refusal): self.execute(reviewed)
        self.execute(self.reviewed())
        self.assertEqual(list(second.iterdir()), [])
        self.assertTrue(all(p.exists() for p in evidence))

    def test_erase_detects_late_child_and_inode_replacement(self):
        with m.directory(self.app) as fd:
            entries = m.tree(fd, [0], m.os.fstat(fd).st_dev, [0])
            (self.app / 'late').write_text('synthetic late writer')
            with self.assertRaises(m.Refusal): m.erase(fd, entries)
            (self.app / 'late').unlink()
            (self.app / 'index').unlink(); (self.app / 'index').write_text('replaced synthetic inode')
            with self.assertRaises(m.Refusal): m.erase(fd, entries)
        self.assertTrue((self.app / 'rows/data.json').exists())

    def test_final_inactivity_failure_is_not_reported_as_success(self):
        reviewed = self.reviewed(); original = m.verify_inactive; calls = [0]
        def reactivated(managers):
            calls[0] += 1
            if not list(self.app.iterdir()): raise m.Refusal('mock post-delete reactivation')
            return original(managers)
        with patch.object(m, 'verify_inactive', side_effect=reactivated), self.assertRaises(m.Refusal):
            self.execute(reviewed)
        records = [m.strict(p.read_bytes()) for p in (self.root / '.host-reset').glob('*-result.json')]
        self.assertEqual(records[0]['phase'], 'failed-partial-no-automatic-retry')


    def test_seven_actor_real_model_data_reset_is_not_complete_clean_reset(self):
        rows = self.lab_model()
        caches = {str(self.cache): self.cache.read_bytes(), str(self.failed): self.failed.read_bytes()}
        journal = (self.root / '.install-intent.json').read_bytes()
        with patch.object(m, 'run_read', side_effect=self.offline_read):
            reviewed = self.reviewed()
            self.assertEqual(len(reviewed['plan']['subordinateAllocations']['actors']), 7)
            self.assertEqual(reviewed['plan']['directories'][0]['path'], str(self.app))
            self.assertTrue(all(d['offline'] for d in reviewed['plan']['managers'][1:]))
            result = self.execute(reviewed)
        self.assertEqual(result['phase'], 'empty-owned-app-data')
        self.assertFalse(result['completeCleanReset'])
        self.assertEqual(result['resetClass'], 'engineering-data-only-not-complete-clean')
        self.assertEqual(list(self.app.iterdir()), [])
        self.assertEqual((self.root / '.install-intent.json').read_bytes(), journal)
        for filename, content in caches.items(): self.assertEqual(Path(filename).read_bytes(), content)
        for row in rows:
            for key in ('stateRoot', 'graphRoot', 'volumeRoot'): self.assertTrue(Path(row[key]).is_dir())

    def test_copy_shared_and_rootful_roots_follow_generator_not_global_copy_source(self):
        rows = self.lab_model()
        global_source = Path(self.ir['volumes']['database']['hostPath'])
        global_source.mkdir(parents=True, mode=0o700)
        (global_source / 'keep').write_text('not persistent copy-domain data')
        shared = self.scope / 'shared'; shared.mkdir(mode=0o700)
        (shared / 'data').write_text('synthetic shared')
        rootful = self.scope / 'rootful'; rootful.mkdir(mode=0o700)
        (rootful / 'data').write_text('synthetic rootful')
        self.ir['volumes'].update(shared={'hostPath': str(shared), 'rootlessStrategy': 'shared'},
                                  rootful={'hostPath': str(rootful)})
        self.ir['services']['db']['volumes'].append({'source': 'shared', 'target': '/shared'})
        self.ir['services']['root'] = {'placement': 'rootful', 'volumes': ['rootful:/data']}
        self.seal('retired-failed')
        with patch.object(m, 'run_read', side_effect=self.offline_read):
            reviewed = self.reviewed()
            self.assertEqual({d['path'] for d in reviewed['plan']['directories']}, {str(self.app), str(shared), str(rootful)})
            self.execute(reviewed)
        self.assertEqual((global_source / 'keep').read_text(), 'not persistent copy-domain data')
        self.assertFalse(list(shared.iterdir())); self.assertFalse(list(rootful.iterdir()))

    def test_cross_domain_mapped_uid_and_gid_are_refused(self):
        self.lab_model()
        with patch.object(m, 'run_read', side_effect=self.offline_read):
            for uid, gid in ((2065536, 2000000), (2000000, 2065536), (786, 780), (2000000 + 65536, 780)):
                with self.subTest(uid=uid, gid=gid):
                    self.owned(self.app / 'index', uid, gid); self.denied()

    def test_mapped_leaf_root_is_supported_only_in_its_own_private_domain(self):
        self.lab_model(); self.owned(self.app, 2000000 + 999)
        with patch.object(m, 'run_read', side_effect=self.offline_read):
            self.assertEqual(self.execute()['phase'], 'empty-owned-app-data')

    def test_scope_actor_acl_cannot_gain_write_or_foreign_execute(self):
        self.lab_model(); key = (REAL_STAT(self.scope).st_dev, REAL_STAT(self.scope).st_ino)
        baseline = self.acl_overrides[key]
        for entry in ([2, 3, 780], [2, 1, 999999], [8, 1, 2000]):
            self.acl_overrides[key] = [r for r in baseline if not (r[0] == entry[0] and r[2] == entry[2])] + [entry]
            with self.subTest(entry=entry), patch.object(m, 'run_read', side_effect=self.offline_read): self.denied()
        self.acl_overrides[key] = baseline

    def test_exact_namespace_root_execute_acl_supported_not_whole_interval(self):
        self.lab_model(); key = (REAL_STAT(self.scope).st_dev, REAL_STAT(self.scope).st_ino)
        self.acl_overrides[key] += [[2, 1, 2000000]]; self.acl_overrides[key].sort()
        with patch.object(m, 'run_read', side_effect=self.offline_read): self.reviewed()
        self.acl_overrides[key] += [[2, 1, 2000001]]
        with patch.object(m, 'run_read', side_effect=self.offline_read): self.denied()

    def test_operator_scope_wrong_uid_gid_mode_and_link_refused(self):
        self.lab_model()
        with patch.object(m, 'run_read', side_effect=self.offline_read):
            for uid, gid, mode in ((1001, 2000, 0o2770), (1000, 999, 0o2770), (1000, 2000, 0o2777)):
                self.owned(self.scope, uid, gid); self.scope.chmod(mode)
                with self.subTest(uid=uid, gid=gid, mode=mode): self.denied()
            self.owned(self.scope, 1000, 2000); self.scope.chmod(0o2770)
            moved = self.base / 'moved'; self.scope.rename(moved); self.scope.symlink_to(moved)
            self.denied()

    def test_actor_private_parent_permissions_and_primary_group_are_exact(self):
        self.lab_model(); parent = Path(self.row['volumeRoot'])
        with patch.object(m, 'run_read', side_effect=self.offline_read):
            parent.chmod(0o710); self.denied(); parent.chmod(0o700)
            self.owned(parent, 780, 781); self.denied()

    def test_subordinate_allocation_shape_overlap_and_host_identity_fail_closed(self):
        cases = [b'fixture-app:2000000:65535\n',
                 b'fixture-app:2000000:65536\nfixture-app:4000000:65536\n',
                 b'fixture-app:2000000:65536\nforeign:2000001:65536\n',
                 b'fixture-app:2000000:65536\n780:2000001:65536\n', b'malformed\n']
        for raw in cases:
            with self.subTest(raw=raw), patch.object(m, 'read_allocation_files', return_value={'subuid': raw, 'subgid': raw}): self.denied()
        files = self.allocation_files(); files['subgid'] = b'fixture-app:3000000:65536\n'
        with patch.object(m, 'read_allocation_files', return_value=files): self.denied()
        with patch.object(m, 'identity_ids', return_value=[2000001]): self.denied()

    def test_selected_allocation_changes_invalidate_review_and_post_intent(self):
        reviewed = self.reviewed()
        files = {n: b'fixture-app:3000000:65536\n' for n in ('subuid', 'subgid')}
        with patch.object(m, 'read_allocation_files', return_value=files): self.denied(lambda: self.execute(reviewed))
        original = m.write_evidence
        with patch.object(m, 'read_allocation_files', side_effect=self.allocation_files) as reader:
            def drift(fd, filename, value):
                original(fd, filename, value)
                if filename.endswith('-intent.json'): reader.side_effect = None; reader.return_value = files
            with patch.object(m, 'write_evidence', side_effect=drift): self.denied(lambda: self.execute(reviewed))

    def test_owned_symlinks_are_inert_even_to_forbidden_or_missing_targets(self):
        forbidden = self.app / 'outside'; forbidden.symlink_to('/forbidden-private-target-never-open')
        (self.app / 'dangling').symlink_to('missing-target')
        (self.app / 'loop').symlink_to('loop')
        original = m.os.readlink
        def pointer_only(value, *args, **kwargs):
            if value != 'current': raise AssertionError('app symlink target read')
            return original(value, *args, **kwargs)
        with patch.object(m.os, 'readlink', side_effect=pointer_only):
            reviewed = self.reviewed()
            links = [e for e in reviewed['plan']['directories'][0]['children'] if e.get('inertSymlink')]
            self.assertEqual(len(links), 3)
            self.execute(reviewed)
        self.assertTrue(self.cache.exists())

    def test_foreign_and_hardlinked_symlinks_refused(self):
        item = self.app / 'link'; item.symlink_to('/never-read')
        self.foreign(item); self.denied(); self.uid_overrides.clear()
        os.link(item, self.app / 'alias', follow_symlinks=False); self.denied()

    def test_symlink_inode_drift_blocks_reviewed_reset(self):
        item = self.app / 'link'; item.symlink_to('/never-read-a')
        reviewed = self.reviewed(); item.unlink(); item.symlink_to('/never-read-b')
        self.denied(lambda: self.execute(reviewed))

    def test_stopped_manager_proof_never_queries_or_starts_user_manager(self):
        self.lab_model()
        with patch.object(m, 'run_read', side_effect=self.offline_read): self.execute()
        self.assertFalse(any('start' in c or 'enable' in c for c in self.calls))
        self.assertTrue(any('SYSTEMD_OFFLINE=1' in c for c in self.calls))
        self.assertTrue(self.offline.called)

    def test_stopped_manager_trigger_or_journal_failure_prevents_deletion(self):
        self.lab_model()
        for state in ('enabled', 'static', 'generated', 'unknown'):
            def unsafe(command):
                if 'is-enabled' in command:
                    units = command[command.index('is-enabled') + 1:]
                    return SimpleNamespace(returncode=0, stdout=(state + '\n') * len(units))
                return self.offline_read(command)
            with self.subTest(state=state), patch.object(m, 'run_read', side_effect=unsafe): self.denied()
        self.offline.side_effect = ValueError('canonical stopped/no-linger/process proof refused')
        self.denied()

    def test_stopped_manager_becomes_active_after_intent_is_not_contacted(self):
        self.lab_model()
        with patch.object(m, 'run_read', side_effect=self.offline_read):
            reviewed = self.reviewed(); original = m.write_evidence
            def changed(fd, filename, value):
                original(fd, filename, value)
                if filename.endswith('-intent.json'): self.offline.return_value = False
            with patch.object(m, 'write_evidence', side_effect=changed): self.denied(lambda: self.execute(reviewed))

    def install_fixture_configs(self):
        homes = self.base / 'homes'; homes.mkdir(mode=0o700)
        for row in self.metadata['domains']:
            home = homes / row['user']; home.mkdir(mode=0o700); self.owned(home, row['uid'])
            for suffix in ('.config', '.config/containers', '.config/containers/systemd', '.config/systemd', '.config/systemd/user'):
                d = home / suffix; d.mkdir(mode=0o700); self.owned(d, row['uid'])
            generated = self.release / 'quadlet' / ('rootless-' + row['name'])
            for src in generated.iterdir():
                dest = home / ('.config/systemd/user' if src.suffix == '.target' else '.config/containers/systemd') / src.name
                dest.write_bytes(src.read_bytes()); dest.chmod(0o644); self.owned(dest, row['uid'])
        return homes

    def test_actor_owned_installed_configs_require_exact_source_hash_and_identity(self):
        self.lab_model(); homes = self.install_fixture_configs()
        source = homes / self.row['user'] / '.config/containers/systemd/webservices-db.container'
        with patch.object(m, 'run_read', side_effect=self.offline_read):
            reviewed = self.reviewed()
            virtual = '/home/' + self.row['user'] + '/.config/containers/systemd/webservices-db.container'
            self.assertEqual(reviewed['plan']['authorityFiles'][virtual]['actor'], 780)
            self.execute(reviewed)
        self.assertTrue(source.exists())

    def test_actor_config_hash_hardlink_foreign_owner_and_symlink_refused(self):
        self.lab_model(); homes = self.install_fixture_configs()
        source = homes / self.row['user'] / '.config/containers/systemd/webservices-db.container'
        original = source.read_bytes()
        with patch.object(m, 'run_read', side_effect=self.offline_read):
            source.write_bytes(b'changed'); self.denied(); source.write_bytes(original)
            self.owned(source, 781); self.denied(); self.owned(source, 780)
            alias = self.base / 'config-alias'; os.link(source, alias); self.denied(); alias.unlink()
            source.unlink(); source.symlink_to('/forbidden-never-read'); self.denied()

    def test_actor_config_replaced_same_bytes_or_added_after_review_is_cas_drift(self):
        self.lab_model(); homes = self.install_fixture_configs()
        source = homes / self.row['user'] / '.config/containers/systemd/webservices-db.container'
        with patch.object(m, 'run_read', side_effect=self.offline_read):
            reviewed = self.reviewed(); raw = source.read_bytes(); source.unlink(); source.write_bytes(raw)
            self.owned(source, 780); self.denied(lambda: self.execute(reviewed))

    def test_stage_source_and_actor_acl_drift_after_intent_are_refused(self):
        self.lab_model()
        with patch.object(m, 'run_read', side_effect=self.offline_read):
            for kind in ('stage', 'acl'):
                reviewed = self.reviewed(); original = m.write_evidence
                target = self.release / 'quadlet/rootless-fixture/webservices-db.container'
                saved = target.read_bytes(); key = (REAL_STAT(self.scope).st_dev, REAL_STAT(self.scope).st_ino)
                acl = list(self.acl_overrides[key])
                def changed(fd, filename, value):
                    original(fd, filename, value)
                    if filename.endswith('-intent.json'):
                        if kind == 'stage': target.write_bytes(saved + b'\n')
                        else: self.acl_overrides[key] = [r for r in acl if r != [2, 1, 780]]
                with self.subTest(kind=kind), patch.object(m, 'write_evidence', side_effect=changed):
                    self.denied(lambda: self.execute(reviewed))
                target.write_bytes(saved); self.acl_overrides[key] = acl

    def test_journal_adapter_calls_canonical_offline_functions_and_suppresses_cache(self):
        row = dict(self.row); command = ['mock-only']
        def actor(release, label):
            self.assertTrue(sys.dont_write_bytecode)
            return row
        journal = SimpleNamespace(offline_actor=actor,
                                  verify_offline_actor=lambda actor, cmd: self.assertEqual(cmd, command))
        fake_spec = SimpleNamespace()
        with patch.object(m.importlib.util, 'spec_from_file_location', return_value=fake_spec), \
             patch.object(m.importlib.util, 'module_from_spec', return_value=journal), \
             patch.object(m, 'read_file', return_value=b''), \
             patch.object(sys, 'dont_write_bytecode', False):
            self.assertTrue(REAL_JOURNAL_OFFLINE(self.release, row, command))
            self.assertFalse(sys.dont_write_bytecode)
            journal.offline_actor = lambda release, label: None
            self.assertFalse(REAL_JOURNAL_OFFLINE(self.release, row, command))
            self.assertFalse(sys.dont_write_bytecode)

    def test_generator_runtime_binds_are_preserved_not_mistaken_for_named_data(self):
        self.ir['services']['db']['volumes'] += [
            './configs/app.yaml:/config:ro', './build/tool:/tool:ro', './repos:/repos',
            './repos/example:/example', './stack.containers/source:/source:ro',
            '/etc/resolv.conf:/etc/resolv.conf:ro', self.row['stateRoot'] + '/runtime-env:/env:ro']
        self.seal(); self.execute()
        self.assertTrue(self.cache.exists()); self.assertTrue(self.failed.exists())

    def test_unknown_persistent_direct_bind_and_foreign_domain_refused(self):
        self.ir['services']['db']['volumes'].append(str(self.sibling) + ':/data')
        self.seal(); self.denied()
        self.ir['services']['db'] = {'placement': 'rootless', 'rootlessDomain': 'foreign', 'volumes': ['database:/data']}
        self.seal(); self.denied()

    def test_receipted_subordinate_start_is_not_silently_reassigned(self):
        # subuidStart belongs to metadata, not the deliberately minimal storage marker.
        self.metadata['domains'] = [dict(self.row, subuidStart=3000000)]
        self.seal(); self.denied()
        self.metadata['domains'][0]['subuidStart'] = 2000000; self.seal(); self.reviewed()

    def test_acl_wire_parser_is_fd_only_and_fail_closed(self):
        import errno
        import struct
        raw = struct.pack('<I', 2) + struct.pack('<HHI', 2, 1, 780)
        with patch.object(m.os, 'getxattr', return_value=raw) as getter:
            self.assertEqual(REAL_ACCESS_ACL(123), [[2, 1, 780]])
            getter.assert_called_once_with(123, 'system.posix_acl_access')
        for raw in (b'', struct.pack('<I', 3), struct.pack('<I', 2) + b'x',
                    struct.pack('<I', 2) + struct.pack('<HHI', 2, 8, 780)):
            with self.subTest(raw=raw), patch.object(m.os, 'getxattr', return_value=raw):
                with self.assertRaises(m.Refusal): REAL_ACCESS_ACL(123)
        with patch.object(m.os, 'getxattr', side_effect=OSError(errno.ENODATA, 'mock no ACL')):
            self.assertEqual(REAL_ACCESS_ACL(123), [])
        with patch.object(m.os, 'getxattr', side_effect=PermissionError('mock denied ACL')):
            with self.assertRaises(PermissionError): REAL_ACCESS_ACL(123)

    def test_canonical_runtime_environment_source_and_only_known_dropin(self):
        destination = self.base / 'units'; destination.mkdir(mode=0o700)
        authority, dropin = m.runtime_env_authority(destination, str(self.root), '/run/webservices')
        expected = ('[Unit]\nDescription=Restore rendered webservices environment files\n\n'
                    '[Service]\nType=oneshot\nWorkingDirectory=/\n'
                    "ExecStart=/bin/sh -ec '/usr/bin/install -d -m 0700 /run/webservices; for env_file in " +
                    str(self.root) + '/runtime-env/*.env; do [ -e "$env_file" ] || continue; '
                    '/usr/bin/install -m 0600 "$env_file" /run/webservices/; done\'\nRemainAfterExit=yes\n')
        self.assertEqual(authority['sha256'], m.sha(expected.encode()))
        target = destination / 'webservices.target'; target.write_text('[Unit]\nDescription=Synthetic\n')
        extra = Path(dropin['source']); extra.parent.mkdir(mode=0o700)
        extra.write_bytes(b'[Unit]\nRequires=webservices-runtime-env.service\nAfter=webservices-runtime-env.service\n')
        managers = [{'manager': 'fixture', 'command': ['mock-only'],
                     'units': {'webservices.target': {'source': str(target), 'sha256': m.sha(target.read_bytes())}},
                     'dropins': {'webservices.target': dropin}}]
        def loaded(command):
            result = self.unit_read(command)
            if 'show' not in command: return result
            values = dict(line.split('=', 1) for line in result.stdout.splitlines())
            values.update(LoadState='loaded', UnitFileState='disabled', FragmentPath=str(target), DropInPaths=str(extra))
            result.stdout = ''.join(k + '=' + v + '\n' for k, v in values.items())
            return result
        with patch.object(m, 'run_read', side_effect=loaded):
            m.verify_inactive(managers)
            extra.write_bytes(extra.read_bytes() + b'\n')
            with self.assertRaises(m.Refusal): m.verify_inactive(managers)

    def test_canonical_offline_manager_linger_process_and_jobs_gate_is_reused(self):
        # Run the actual tracked journal functions against entirely isolated
        # synthetic paths/replies, never its native process/package readers.
        import types
        journal_file = REPO / 'runtime-generator/podman-ops/install-journal.py'
        journal = types.ModuleType('isolated_journal'); journal.__file__ = str(journal_file)
        exec(compile(journal_file.read_bytes(), str(journal_file), 'exec'), journal.__dict__)
        proc = self.base / 'proc'; proc.mkdir(mode=0o700)
        process = proc / '123'; process.mkdir(mode=0o700)
        status = process / 'status'; status.write_text('Name:\tsynthetic\nUid:\t0\t0\t0\t0\n')
        linger = self.base / 'linger'; linger.mkdir(mode=0o700)
        real_path = Path
        def isolated_path(value):
            if str(value) == '/proc': return proc
            if str(value) == '/var/lib/systemd/linger': return linger
            return real_path(value)
        manager = 'user@' + str(self.row['uid']) + '.service'
        controls = {'active': 'inactive', 'sub': 'dead', 'job': '', 'enabled': 'disabled', 'jobs': ''}
        def probe(command, **kwargs):
            self.assertNotIn('start', command); self.assertNotIn('enable', command)
            if 'show' in command:
                self.assertNotIn('--user', command)
                props = {'Id': manager, 'LoadState': 'loaded', 'ActiveState': controls['active'],
                         'SubState': controls['sub'], 'MainPID': '0', 'Job': controls['job']}
                return SimpleNamespace(returncode=0, stdout=''.join(k + '=' + v + '\n' for k, v in props.items()))
            if 'is-enabled' in command:
                self.assertIn('SYSTEMD_OFFLINE=1', command)
                return SimpleNamespace(returncode=1, stdout=controls['enabled'] + '\n' + controls['enabled'] + '\n')
            if 'list-jobs' in command: return SimpleNamespace(returncode=0, stdout=controls['jobs'])
            raise AssertionError('unexpected native command shape')
        # Use a real module spec for __file__, but compile FD-pinned journal bytes
        # in the adapter (no source-cache loader or host read).
        with patch.object(m.importlib.util, 'module_from_spec', return_value=journal), \
             patch.object(journal.subprocess, 'run', side_effect=probe), \
             patch.object(m, 'read_file', return_value=b''):
            # Empty compile leaves actual journal functions installed; globals
            # below are patched only AFTER initial module execution.
            with patch.object(journal, 'Path', side_effect=isolated_path), \
                 patch.object(journal, 'offline_subordinate_start', return_value=2000000):
                command = ['runuser', '-u', self.row['user'], '--', 'env', 'HOME=/home/fixture-app', 'systemctl', '--user']
                self.assertTrue(REAL_JOURNAL_OFFLINE(self.release, self.row, command))
                (linger / self.row['user']).touch()
                with self.assertRaises(ValueError): REAL_JOURNAL_OFFLINE(self.release, self.row, command)
                (linger / self.row['user']).unlink()
                for uid in (self.row['uid'], 2000000, 2065535):
                    status.write_text('Uid:\t0\t' + str(uid) + '\t0\t0\n')
                    with self.subTest(uid=uid), self.assertRaises(ValueError):
                        REAL_JOURNAL_OFFLINE(self.release, self.row, command)
                status.write_text('Uid:\t0\t0\t0\t0\n')
                for key, value in (('job', '7'), ('enabled', 'enabled'), ('jobs', '1 ' + manager + ' start waiting\n')):
                    saved = controls[key]; controls[key] = value
                    with self.subTest(key=key), self.assertRaises(ValueError):
                        REAL_JOURNAL_OFFLINE(self.release, self.row, command)
                    controls[key] = saved
                controls.update(active='active', sub='running')
                self.assertFalse(REAL_JOURNAL_OFFLINE(self.release, self.row, command))

    def test_canonical_shared_acl_mask_is_not_a_foreign_group_write_adoption(self):
        self.lab_model()
        shared = self.scope / 'shared'; shared.mkdir(mode=0o700)
        data = shared / 'data'; data.write_text('synthetic shared app data')
        self.ir['volumes']['shared'] = {'hostPath': str(shared), 'rootlessStrategy': 'shared'}
        self.ir['services']['db']['volumes'].append('shared:/shared')
        self.seal('retired-failed')
        shared.chmod(0o770); data.chmod(0o660)
        def acl(item, uid, rights):
            info = REAL_STAT(item)
            rows = [[1, 7 if item.is_dir() else 6, 2**32 - 1], [4, 0, 2**32 - 1],
                    [16, rights, 2**32 - 1], [32, 0, 2**32 - 1], [2, rights, uid]]
            self.acl_overrides[(info.st_dev, info.st_ino)] = sorted(rows)
        acl(shared, 780, 7); acl(data, 780, 6)
        with patch.object(m, 'run_read', side_effect=self.offline_read):
            self.reviewed()
            acl(shared, 781, 7); self.denied(); acl(shared, 780, 7)
            acl(data, 781, 6); self.denied(); acl(data, 780, 6)
            self.ir['volumes']['shared']['rootlessAccess'] = 'read-only'; self.seal('retired-failed'); self.denied()
            self.ir['volumes']['shared']['rootlessAccess'] = 'read-write'; self.seal('retired-failed')
            result = self.execute()
        self.assertEqual(set(result['emptied']), {str(shared), str(self.app)})
        self.assertFalse(list(shared.iterdir()))

    def test_previously_absent_actor_config_cannot_appear_after_intent(self):
        self.lab_model()
        with patch.object(m, 'run_read', side_effect=self.offline_read):
            reviewed = self.reviewed(); original = m.write_evidence
            def added(fd, filename, value):
                original(fd, filename, value)
                if filename.endswith('-intent.json'): self.install_fixture_configs()
            with patch.object(m, 'write_evidence', side_effect=added): self.denied(lambda: self.execute(reviewed))

if __name__ == '__main__': unittest.main(verbosity=2)
