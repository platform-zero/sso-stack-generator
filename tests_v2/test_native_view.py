"""Critical07 source-only containment/protocol fixtures; NO Root/native execution."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(filename):
    spec = importlib.util.spec_from_file_location(filename.replace('-', '_'), ROOT / 'ops/host-admin' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


n = load('provision-p0-v2-view.py')
legacy = load('provision-p0-v2-namespace.py')
credentials = load('provision-p0-machine-credentials.py')
relays = load('provision-p0-v2-relays.py')


def node(inode, device=1, fsid=5, uid=0, gid=0, mode=0o711):
    return {'device': device, 'inode': inode, 'filesystemId': fsid, 'uid': uid, 'gid': gid, 'mode': mode}


def previous():
    parent = {'id': 100, 'parent': 1, 'device': '0:1', 'root': '/', 'target': '/mnt/stack',
              'options': ['rw'], 'optional': [], 'fsType': 'ext4', 'source': '/fixture'}
    mount = dict(parent, id=101, parent=100, root='/p0-v2', target=str(n.PHYSICAL))
    return n.seal({'version': 2, 'state': 'pinned', 'owner': 'a' * 32, 'evidenceSha256': 'b' * 64,
        'namespace': {'device': 1, 'inode': 20, 'filesystemId': 5},
        'bootId': '12345678-1234-1234-1234-123456789abc', 'mountNamespace': {'device': 4, 'inode': 9},
        'mount': mount, 'cloneMountId': 101})


def projected(parent=None, data=None, ns=90):
    parent, data = parent or node(10), data or node(20)
    return {'parent': parent, 'data': data, 'mountNamespace': {'device': 4, 'inode': ns},
        'parentMount': {'id': 200, 'parent': 1, 'target': '/mnt/stack', 'device': n.device(parent), 'optional': []},
        'dataMount': {'id': 201, 'parent': 200, 'target': str(n.PHYSICAL), 'device': n.device(data), 'optional': []}}


def complete_fixture():
    before = previous()
    anchor = {'parent': node(10), 'data': node(20), 'mountId': 150}
    witness = n.unshare_witness(anchor['parent'], anchor['data'], node(30, uid=1004, gid=1004, mode=0o700),
                                [[0, 1004, 1], [1, 300000, 65536]], [[0, 1004, 1], [1, 300000, 65536]])
    record = n.seal({'version': 3, 'state': 'complete', 'owner': before['owner'], 'previousSha256': n.sha(n.encoded(before)),
        'evidenceSha256': before['evidenceSha256'], 'bootId': before['bootId'], 'data': before['namespace'], 'anchor': anchor,
        'native': {'handle': {'device': 4, 'inode': 90, 'mountId': 160, 'type': 'mnt', 'fsType': 'nsfs'}, 'projection': projected()},
        'manager': {'unit': n.MANAGER, 'dropinSha256': n.sha(n.DROPIN_BYTES), 'projection': projected(ns=91)},
        'pause': {'oldPauseClosed': True, 'actualUnshareWitness': witness,
                  'actualUnshareResult': {'version': 1, 'scope': 'p0-native-view-probe', 'guarded': True}}})
    observation = {k: copy.deepcopy(record[k]) for k in ('bootId', 'anchor', 'native', 'manager', 'pause')}
    return record, observation


class ContainmentTests(unittest.TestCase):
    def test_v2_namespace_pin_all_modes_refuse_before_any_filesystem_or_native(self):
        for mode in ('apply', 'resume', 'recheck', 'review-units', 'status', 'check'):
            with patch.object(legacy, 'namespace') as fs:
                with self.subTest(mode=mode), self.assertRaisesRegex(legacy.Refused, '^protected-view-v3-integration-required$'):
                    legacy.pin(None, None, None, None, None, mode)
                fs.assert_not_called()

    def test_credential_authority_refuses_before_old_marker_observation(self):
        with patch.object(credentials, 'read_exact') as read:
            with self.assertRaisesRegex(credentials.Refused, '^protected-view-v3-integration-required$'):
                credentials.pinned_namespace()
            read.assert_not_called()

    def test_relay_publication_authority_refuses_before_private_store_or_target_effects(self):
        with patch.object(relays.Marker, 'open') as opened:
            with self.assertRaisesRegex(relays.Refused, '^protected-view-v3-integration-required$'):
                relays.Authority({}, 'a' * 64)
            opened.assert_not_called()

    def test_no_root_prefix_even_from_self_consistent_fixture_v3_until_integration(self):
        record, observation = complete_fixture()
        n.complete(record, observation)  # Schema/mechanism only, NOT kernel authority.
        with self.assertRaisesRegex(n.Refused, '^native-view-consumer-integration-required$'):
            n.root_prefix(record, observation)
        argv = n.proposed_root_prefix(record, observation)
        self.assertEqual(argv[:4], ['/usr/bin/nsenter', '--mount=' + str(n.HANDLE), '--', '/usr/bin/podman'])
        self.assertIn('/mnt/stack/p0-v2/rootful/engine', argv)
        self.assertNotIn('/proc/self/fd/', repr(argv))

    def test_legacy_geometry_reports_are_explicitly_unsafe(self):
        report = legacy.report(previous(), 'fixture-mechanism-only')
        self.assertFalse(report['secureAuthority'])
        self.assertFalse(report['existingRootfulRepinSupported'])
        self.assertTrue(report['protectedViewRequired'])
        self.assertFalse(report['installationCertified'])

    def test_production_transition_closed_before_all_effects(self):
        raw = n.encoded(previous())
        store = types.SimpleNamespace(load=lambda: None, save=lambda *a: self.fail('unqualified effect'))
        with self.assertRaisesRegex(n.Refused, '^native-manager-pause-gates-unqualified$'):
            n.Transition(store, n.ClosedHost()).apply(raw, n.sha(raw), previous()['namespace'])


class ContractTests(unittest.TestCase):
    def test_prior_v2_is_bootstrap_only_and_requires_exact_complete_hash_owner_identity(self):
        good = previous()
        raw = n.encoded(good)
        self.assertEqual(n.previous_claim(raw, n.sha(raw), good['namespace'])['owner'], good['owner'])
        for mutation in (lambda r: r.update(state='claimed'), lambda r: r.update(owner='bad'),
                         lambda r: r.update(cloneMountId=999), lambda r: r['namespace'].update(inode=999),
                         lambda r: r['mount'].update(optional=['shared:7'])):
            bad = copy.deepcopy(good)
            mutation(bad)
            n.seal(bad)
            raw = n.encoded(bad)
            with self.subTest(record=bad), self.assertRaises(n.Refused):
                n.previous_claim(raw, n.sha(raw), good['namespace'])
        with self.assertRaisesRegex(n.Refused, '^previous-sha256$'):
            n.previous_claim(n.encoded(good), '0' * 64, good['namespace'])

    def test_mutable_parent_and_same_old_mount_id_do_not_satisfy_projection(self):
        good = projected()
        n.projection(good, node(10), node(20))
        bad = copy.deepcopy(good)
        bad['parent'] = node(999, uid=1000, gid=1000, mode=0o2775)
        # Native10 SAME data/mountID is expressly insufficient.
        with self.assertRaises(n.Refused):
            n.projection(bad, node(10), node(20))
        bad = copy.deepcopy(good)
        bad['parent']['inode'] = 999
        with self.assertRaisesRegex(n.Refused, '^view-identity-changed$'):
            n.projection(bad, node(10), node(20))

    def test_complete_schema_rejects_foreign_handle_manager_pause_boot_and_shared_projection(self):
        good, observation = complete_fixture()
        for mutation in (lambda r: r.update(version=2), lambda r: r.update(state='manager-pending'),
                         lambda r: r['native']['handle'].update(inode=999), lambda r: r['native']['handle'].update(fsType='ext4'),
                         lambda r: r['manager'].update(unit='user@1000.service'),
                         lambda r: r['pause'].update(oldPauseClosed=False),
                         lambda r: r['native']['projection']['dataMount'].update(optional=['shared:7'])):
            bad = copy.deepcopy(good)
            mutation(bad)
            n.seal(bad)
            with self.subTest(record=bad), self.assertRaises(n.Refused):
                n.complete(bad, observation)
        observation['bootId'] = '87654321-1234-1234-1234-123456789abc'
        with self.assertRaisesRegex(n.Refused, '^v3-live-authority-changed$'):
            n.complete(good, observation)

    def test_manager_stopped_exact_instance_no_dropins_no_scope_or_activation(self):
        good = {'unit': n.MANAGER, 'uid': 1004, 'gid': 1004, 'active': 'inactive', 'pid': 0, 'cgroup': '',
                'job': '', 'fragment': '/usr/lib/systemd/system/user@.service', 'dropins': [],
                'sourceHashes': {'template': 'a' * 64}, 'transientKind': 'service'}
        n.manager_stopped(good)
        for key, value in (('unit', 'user@1000.service'), ('active', 'active'), ('pid', 7),
                           ('cgroup', '/unrelated'), ('job', '1/start'), ('dropins', ['/authored.conf']),
                           ('transientKind', 'scope')):
            with self.subTest(key=key), self.assertRaises(n.Refused):
                n.manager_stopped(dict(good, **{key: value}))
        self.assertIn(b'BindPaths=/var/lib/p0-v2-view/stack:/mnt/stack', n.DROPIN_BYTES)
        self.assertIn(b'PrivateMounts=yes', n.DROPIN_BYTES)
        self.assertNotIn(b'Restart=', n.DROPIN_BYTES)

    def test_pause_missing_pidfile_or_integer_pid_is_never_signal_authority(self):
        for observation in (None, {'pid': 777}, {'pid': 777, 'uid': 1004}):
            with self.subTest(observation=observation), self.assertRaisesRegex(n.Refused, '^pause-executable-profile-unqualified$'):
                n.pause_identity(observation)
        with self.assertRaisesRegex(n.Refused, '^pause-schema$'):
            n.pause_identity({'pid': 777}, executable_profile_qualified=True)


class UnshareTests(unittest.TestCase):
    def setUp(self):
        self.record, _ = complete_fixture()
        self.witness = self.record['pause']['actualUnshareWitness']
        self.namespace = {'__name__': 'unprivileged_probe_fixture'}
        exec(compile(n.UNSHARE_PROGRAM, '<fixed-unprivileged-metadata-probe>', 'exec'), self.namespace)
        self.actual = {key: dict(self.witness[key]) for key in ('parent', 'data', 'engine')}
        self.rows = [[0, 1004, 1], [1, 300000, 65536]]
        self.opened = []
        def open_file(path, mode):
            if path.endswith(('/uid_map', '/gid_map')):
                return io.BytesIO(('\n'.join(' '.join(map(str, r)) for r in self.rows) + '\n').encode())
            return io.BytesIO(b'65534\n')
        def open_node(path, flags):
            self.assertTrue(flags & os.O_PATH)
            key = 'engine' if path.endswith('/engine') else ('data' if path.endswith('/p0-v2') else 'parent')
            self.opened.append(key)
            return key
        def info(key):
            value = self.actual[key]
            # BOTH Host0 and mutable Host1000 are unmapped ->65534. Inode MUST disambiguate.
            return types.SimpleNamespace(st_dev=value['device'], st_ino=value['inode'],
                st_uid=0 if value['uid'] == 1004 else 65534, st_gid=0 if value['gid'] == 1004 else 65534,
                st_mode=stat.S_IFDIR | value['mode'])
        self.namespace['open'] = open_file
        self.namespace['os'] = types.SimpleNamespace(open=open_node, close=lambda *a: None, fstat=info,
            fstatvfs=lambda key: types.SimpleNamespace(f_fsid=self.actual[key]['filesystemId']), geteuid=lambda: 0,
            getegid=lambda: 0, O_PATH=os.O_PATH, O_NOFOLLOW=os.O_NOFOLLOW, O_DIRECTORY=os.O_DIRECTORY)

    def test_actual_child_view_accepts_same_protected_inode_with_overflow_owner(self):
        self.assertTrue(self.namespace['probe'](self.witness)['guarded'])
        self.assertEqual(self.opened, ['parent', 'data', 'engine'])

    def test_old_pause_mutable_view_refuses_despite_same_overflow_uid_and_same_data(self):
        self.actual['parent'] = node(999, uid=1000, gid=1000, mode=0o711)
        with self.assertRaises(ValueError):
            self.namespace['probe'](self.witness)
        self.assertEqual(self.opened, ['parent'])

    def test_wrong_map_data_engine_or_fsid_refuses_before_mutation(self):
        for key in ('parent', 'data', 'engine'):
            original = copy.deepcopy(self.actual[key])
            self.actual[key]['filesystemId'] += 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.namespace['probe'](self.witness)
            self.actual[key] = original
        self.rows = [[0, 0, 1]]
        with self.assertRaises(ValueError):
            self.namespace['probe'](self.witness)

    def test_mapping_rejects_overlap_boolean_and_host_root(self):
        for rows in ([[0, 0, 1]], [[False, 1004, 1]], [[0, 1004, 2], [1, 300000, 65536]]):
            with self.subTest(rows=rows), self.assertRaises(n.Refused):
                n.mapping(rows, 1004)


class ReadonlyObserverTests(unittest.TestCase):
    def test_protected_anchor_and_nsfs_reads_never_consult_mutable_source(self):
        record, _ = complete_fixture()
        frames = {10: record['anchor']['parent'], 20: record['anchor']['data']}
        opened, closed = [], []
        def open_node(path, flags):
            opened.append(path)
            return {n.STACK: 10, n.ANCHOR: 20, n.HANDLE: 30}[path]
        def fstat(fd):
            value = frames.get(fd, {'device': 4, 'inode': 90, 'uid': 0, 'gid': 0, 'mode': 0o444})
            return types.SimpleNamespace(st_dev=value['device'], st_ino=value['inode'], st_uid=value['uid'],
                                         st_gid=value['gid'], st_mode=stat.S_IFDIR | value['mode'])
        table = (f'150 1 0:1 /physical-renamed {n.ANCHOR} rw - ext4 /fixture rw\n'
                 f'160 1 0:4 mnt:[90] {n.HANDLE} rw - nsfs nsfs rw\n').encode()
        def bounded(path, limit):
            return record['bootId'].encode() if path.endswith('/boot_id') else table
        view = types.SimpleNamespace(st_dev=4, st_ino=5)
        with patch.object(n, 'root_ancestors'), patch.object(n, 'bounded', side_effect=bounded), \
             patch.object(n.os, 'stat', return_value=view), patch.object(n.os, 'open', side_effect=open_node), \
             patch.object(n.os, 'fstat', side_effect=fstat), patch.object(n.os, 'fstatvfs', side_effect=lambda fd: types.SimpleNamespace(f_fsid=frames[fd]['filesystemId'])), \
             patch.object(n.os, 'close', side_effect=closed.append), patch.object(n.fcntl, 'ioctl', return_value=0x20000):
            self.assertEqual(n.host_anchor_observation(record)['data'], record['anchor']['data'])
        self.assertEqual(opened, [n.STACK, n.ANCHOR, n.HANDLE])
        self.assertEqual(closed, [10, 20, 30])
        self.assertNotIn(n.PHYSICAL, opened)

    def test_physical_capacity_uses_data_fd_not_shadow_rootfs_parent(self):
        data = node(20)
        root_calls = []
        def root_space(path):
            root_calls.append(path)
            return types.SimpleNamespace(f_bavail=60 * 1024**3, f_frsize=1)
        with patch.object(n, 'fd_node', return_value=data), \
             patch.object(n.os, 'fstatvfs', return_value=types.SimpleNamespace(f_bavail=101 * 1024**3, f_frsize=1)), \
             patch.object(n.os, 'statvfs', side_effect=root_space):
            n.data_reserves(200, {k: data[k] for k in ('device', 'inode', 'filesystemId')}, available_ram=17 * 1024**3)
        self.assertEqual(root_calls, ['/', '/var/lib'])
        with patch.object(n, 'fd_node', return_value=data), \
             patch.object(n.os, 'fstatvfs', return_value=types.SimpleNamespace(f_bavail=99 * 1024**3, f_frsize=1)):
            with self.assertRaisesRegex(n.Refused, '^physical-stack-reserve$'):
                n.data_reserves(200, {k: data[k] for k in ('device', 'inode', 'filesystemId')}, available_ram=17 * 1024**3)


class MountProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp = self.enterContext(tempfile.TemporaryDirectory(prefix='.p0-view-source07-', dir=Path.home()))
        self.root = Path(self.temp)
        for name in ('source', 'independent-target'):
            (self.root / name).mkdir()
        self.source = os.open(self.root / 'source', os.O_RDONLY | os.O_DIRECTORY)
        self.target = os.open(self.root / 'independent-target', os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.source)
        self.addCleanup(os.close, self.target)
        self.events = []
        self.tree = None

    def api(self, number, *args):
        if number == 428:
            self.events.append('clone-source')
            self.assertEqual(args[0].value, self.source)
            self.tree = os.dup(self.source)
            return self.tree
        if number == 442:
            self.events.append('private')
            self.assertEqual(args[0].value, self.tree)
            return 0
        if number == 429:
            self.events.append('attach-independent-target')
            self.assertEqual(args[2].value, self.target)
            self.assertNotEqual(args[2].value, self.source)
            self.assertEqual(args[4].value, 0x44)
            return 0
        self.fail('unexpected syscall')

    def test_independent_target_durable_preclaim_before_move_and_post_attach_private(self):
        n.independent_clone(self.api, self.source, self.target, mount_id=lambda fd: 501,
            claim=lambda mid: self.events.append('durable-claim'), before_attach=lambda: self.events.append('stopped-recheck'),
            verify=lambda mid, private: self.events.append('verify-private' if private else 'verify-attached'))
        self.assertEqual(self.events, ['clone-source', 'durable-claim', 'private', 'stopped-recheck',
                                      'attach-independent-target', 'verify-attached', 'private', 'verify-private'])
        with self.assertRaises(OSError):
            os.fstat(self.tree)

    def test_recursive_projection_preclaims_parent_and_child_before_move(self):
        (self.root / 'source/p0-v2').mkdir()
        claims = []
        original = self.api
        def api(number, *args):
            if number == 428:
                self.assertTrue(args[2].value & 0x8000)
            if number == 442:
                self.assertEqual(args[2].value, 0x9000)
            if number == 429:
                self.assertEqual(claims, [{'parent': 501, 'data': 502}])
            return original(number, *args)
        n.recursive_projection(api, self.source, self.target,
            mount_id=lambda fd: 501 if fd == self.tree else 502, claim=lambda ids: claims.append(dict(ids)),
            before_attach=lambda: None, verify=lambda ids, private: None)
        self.assertEqual(claims, [{'parent': 501, 'data': 502}])
        self.assertEqual(self.events.count('private'), 2)
        with self.assertRaises(OSError):
            os.fstat(self.tree)

    def test_duplicate_source_fd_is_not_independent_target(self):
        duplicate = os.dup(self.source)
        self.addCleanup(os.close, duplicate)
        with self.assertRaisesRegex(n.Refused, '^independent-target-required$'):
            n.independent_clone(self.api, self.source, duplicate, mount_id=lambda fd: 501,
                                claim=lambda m: None, before_attach=lambda: None, verify=lambda *a: None)
        self.assertFalse(self.events)

    def test_uncertain_private_verification_retains_effect_no_unmount_cleanup(self):
        def verify(mid, private):
            if private:
                raise n.Refused('synthetic-private-unknown')
        with self.assertRaises(n.Refused):
            n.independent_clone(self.api, self.source, self.target, mount_id=lambda fd: 501,
                                claim=lambda m: None, before_attach=lambda: None, verify=verify)
        self.assertIn('attach-independent-target', self.events)
        with self.assertRaises(OSError):
            os.fstat(self.tree)


class LedgerTests(unittest.TestCase):
    def setUp(self):
        from contextlib import ExitStack
        self.temp = self.enterContext(tempfile.TemporaryDirectory(prefix='.p0-view-ledger07-', dir=Path.home()))
        self.root = Path(self.temp)
        self.stack = self.enterContext(ExitStack())
        real_stat, real_fstat = os.stat, os.fstat
        def mapped(value):
            result = {k: getattr(value, k) for k in dir(value) if k.startswith('st_')}
            result.update(st_uid=0, st_gid=0)
            return types.SimpleNamespace(**result)
        self.stack.enter_context(patch.object(n, 'root_ancestors'))
        self.stack.enter_context(patch.object(n.os, 'stat', side_effect=lambda *a, **k: mapped(real_stat(*a, **k))))
        self.stack.enter_context(patch.object(n.os, 'fstat', side_effect=lambda *a, **k: mapped(real_fstat(*a, **k))))
        self.store = n.ViewStore(self.root / 'private')
        self.store.open(create=True)
        self.addCleanup(self.store.close)
        self.record, _ = complete_fixture()
        self.record.update(state='claimed', anchor=None, native=None, manager=None, pause=None)
        n.seal(self.record)
        self.raw = n.encoded(previous())
        self.record['previousSha256'] = n.sha(self.raw)
        n.seal(self.record)

    def test_private_cas_claim_and_exclusive_exact_previous_retention(self):
        self.store.save(self.record)
        self.store.retain_previous(self.raw, n.sha(self.raw))
        self.assertEqual((self.store.base / 'previous-v2.json').read_bytes(), self.raw)
        self.assertEqual(stat.S_IMODE((self.store.base / 'previous-v2.json').stat().st_mode), 0o400)
        self.assertEqual(self.store.load(), self.record)
        with self.assertRaises(FileExistsError):
            self.store.retain_previous(self.raw, n.sha(self.raw))

    def test_retained_previous_corruption_refuses_and_preserves_bytes(self):
        self.store.save(self.record)
        self.store.retain_previous(self.raw, n.sha(self.raw))
        path = self.store.base / 'previous-v2.json'
        path.chmod(0o600)
        path.write_bytes(b'NEW_CORRUPT_TEST_FIXTURE')
        path.chmod(0o400)
        with self.assertRaisesRegex(n.Refused, '^retained-previous-changed$'):
            self.store.load()
        self.assertEqual(path.read_bytes(), b'NEW_CORRUPT_TEST_FIXTURE')

    def test_same_bytes_replaced_active_inode_fails_cas(self):
        self.store.save(self.record)
        path = self.store.base / 'active.json'
        raw = path.read_bytes()
        path.unlink()  # Exact new TEST fixture only.
        path.write_bytes(raw)
        path.chmod(0o400)
        with self.assertRaisesRegex(n.Refused, '^view-ledger-cas$'):
            self.store.save(self.record)

    def test_failed_private_publication_retained_and_refused_on_reopen(self):
        self.store.save(self.record)
        with patch.object(n.os, 'replace', side_effect=OSError('SYNTHETIC_PRIVATE_PUBLICATION')):
            with self.assertRaises(OSError):
                self.store.save(self.record)
        self.assertTrue((self.store.base / '.publish-active').exists())
        self.store.close()
        with self.assertRaisesRegex(n.Refused, '^view-ledger-interrupted-publication$'):
            self.store.open()

    def test_ledger_directory_swap_refuses_before_publish(self):
        self.store.save(self.record)
        self.store.base.rename(self.root / 'retained-original-ledger-fixture')
        self.store.base.mkdir(mode=0o700)
        with self.assertRaisesRegex(n.Refused, '^view-ledger-directory-changed$'):
            self.store.save(self.record)
        self.assertFalse(list(self.store.base.iterdir()))

    def test_previous_read_is_fixed_hash_bound_and_rejects_links(self):
        path = self.root / 'previous-fixture'
        path.write_bytes(self.raw)
        path.chmod(0o400)
        with patch.object(n, 'PREVIOUS', path):
            self.assertEqual(n.read_previous(n.sha(self.raw))[0], self.raw)
            with self.assertRaisesRegex(n.Refused, '^previous-sha256$'):
                n.read_previous('0' * 64)
            os.link(path, self.root / 'new-fixture-hardlink')
            with self.assertRaisesRegex(n.Refused, '^private-file-custody$'):
                n.read_previous(n.sha(self.raw))


class TransitionTests(unittest.TestCase):
    def setUp(self):
        self.record, self.observation = complete_fixture()
        self.writes, self.effects, self.retained = [], [], []
        self.stored = None
        def save(record):
            self.stored = copy.deepcopy(record)
            self.writes.append(copy.deepcopy(record))
        self.store = types.SimpleNamespace(load=lambda: copy.deepcopy(self.stored), save=save,
            retain_previous=lambda raw, digest: self.retained.append((raw, digest)))
        def target(data):
            self.assertEqual(self.stored['state'], 'claimed')
            self.assertTrue(self.retained)
            self.effects.append('prepare-independent-target')
            return {'parent': node(10), 'cover': node(21), 'data': node(20)}
        def clone(held, claim):
            claim(150)
            self.assertEqual(self.stored['state'], 'anchor-preclaimed')
            self.effects.append('attach')
        def namespace(record):
            self.assertEqual(self.stored['state'], 'native-namespace-claimed')
            self.effects.append('native-private-namespace')
            return self.record['native']
        self.backend = types.SimpleNamespace(preflight=lambda previous: None, boot=lambda: self.record['bootId'],
            prepare_independent_target=target, clone_anchor=clone, observe_anchor=lambda h: self.record['anchor'],
            create_native_namespace=namespace)
        self.transition = n.Transition(self.store, self.backend)
        self.raw = n.encoded(previous())

    def test_retained_previous_and_claims_precede_effects_never_mark_complete(self):
        result = self.transition.apply(self.raw, n.sha(self.raw), previous()['namespace'])
        self.assertEqual(result['state'], 'manager-pending')
        self.assertFalse(result['nativeAuthority'])
        self.assertFalse(result['installationCertified'])
        self.assertEqual(self.retained[0], (self.raw, n.sha(self.raw)))
        self.assertEqual([r['state'] for r in self.writes], list(n.STATES[:-1]))
        with self.assertRaisesRegex(n.Refused, '^v3-incomplete$'):
            n.complete(self.stored, self.observation)

    def test_every_partial_state_refuses_automatic_resume_or_new_boot_replay(self):
        self.transition.apply(self.raw, n.sha(self.raw), previous()['namespace'])
        effects = list(self.effects)
        for mode in ('transition', 'resume'):
            with self.subTest(mode=mode), self.assertRaises(n.Refused):
                self.transition.apply(self.raw, n.sha(self.raw), previous()['namespace'], mode)
            self.assertEqual(self.effects, effects)

    def test_preflight_refusal_precedes_claim_retention_or_target_changes(self):
        self.backend.preflight = lambda *a: (_ for _ in ()).throw(n.Refused('stopped-gate'))
        with self.assertRaises(n.Refused):
            self.transition.apply(self.raw, n.sha(self.raw), previous()['namespace'])
        self.assertFalse(self.writes)
        self.assertFalse(self.retained)
        self.assertFalse(self.effects)


if __name__ == '__main__':
    unittest.main()
