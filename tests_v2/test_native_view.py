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


class Source08MetadataTests(unittest.TestCase):
    def facts(self):
        value = {key: '' for key in n.MANAGER_PROPERTIES}
        value.update(Id=n.MANAGER, LoadState='loaded', ActiveState='inactive', SubState='dead',
            MainPID='0', ControlPID='0', FragmentPath='/usr/lib/systemd/system/user@.service',
            DropInPaths='/usr/lib/systemd/system/user@.service.d/10-login-barrier.conf',
            User='1004', Group='1004', NeedDaemonReload='no')
        return value

    def test_packaged_os_default_is_explicit_hash_profile_not_empty_dropin_assumption(self):
        facts = self.facts()
        raw = b'\n'.join((k + '=' + v).encode() for k, v in facts.items())
        def snapshot(path):
            return {'sha256': n.QUALIFIED_MANAGER_SOURCES[str(path)], 'snapshot': [1] * 9}
        with patch.object(n, 'metadata_call', return_value=raw), patch.object(n, 'binary_snapshot', side_effect=snapshot):
            result = n.MetadataObserver().manager()
        self.assertTrue(result['profileQualified'])
        self.assertEqual(len(result['sources']), 2)
        self.assertIsNone(result['process'])

    def test_unknown_authored_dropin_is_not_read_or_approved(self):
        facts = self.facts()
        facts['DropInPaths'] += ' /etc/systemd/system/user@.service.d/authored.conf'
        raw = b'\n'.join((k + '=' + v).encode() for k, v in facts.items())
        called = []
        def snapshot(path):
            called.append(str(path))
            return {'sha256': n.QUALIFIED_MANAGER_SOURCES[str(path)], 'snapshot': [1] * 9}
        with patch.object(n, 'metadata_call', return_value=raw), patch.object(n, 'binary_snapshot', side_effect=snapshot):
            result = n.MetadataObserver().manager()
        self.assertFalse(result['profileQualified'])
        self.assertEqual(result['unknownDropins'], 1)
        self.assertNotIn('/etc/systemd/system/user@.service.d/authored.conf', called)

    def test_os_default_changed_hash_does_not_qualify(self):
        facts = self.facts()
        raw = b'\n'.join((k + '=' + v).encode() for k, v in facts.items())
        with patch.object(n, 'metadata_call', return_value=raw), patch.object(n, 'binary_snapshot',
                return_value={'sha256': '0' * 64, 'snapshot': [1] * 9}):
            self.assertFalse(n.MetadataObserver().manager()['profileQualified'])

    def test_metadata_command_vocabulary_rejects_mutation_arbitrary_unit_and_extra_args(self):
        for command in (['start', n.MANAGER], ['show', 'user@1000.service'], ['daemon-reload'],
                        ['show', n.MANAGER, '--property=Environment'], ['show', 'p0-v2-x.service', '--all']):
            with self.subTest(command=command), patch.object(n, 'binary_snapshot') as binary:
                with self.assertRaisesRegex(n.Refused, '^metadata-command-not-closed$'):
                    n.metadata_call(command)
                binary.assert_not_called()

    def test_metadata_os_executable_hash_mismatch_refuses_before_spawn(self):
        args = ['show', n.MANAGER, '--property=' + ','.join(n.MANAGER_PROPERTIES)]
        with patch.object(n, 'binary_snapshot', return_value={'sha256': '0' * 64}), \
             patch.object(n.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(n.Refused, '^systemctl-os-code-profile-unqualified$'):
                n.metadata_call(args)
            spawn.assert_not_called()

    def test_unique_boot_target_is_hash_contract_only_without_default_graph_or_authority(self):
        proposal = n.manager_boot_proposal()
        self.assertEqual(proposal['targetSha256'], n.sha(n.BOOT_TARGET_BYTES))
        self.assertEqual(proposal['dropinSha256'], n.sha(n.PROPOSED_MANAGER_BYTES))
        self.assertEqual(proposal['targetMode'], 0o444)  # User1004 must read it; NOT Root0400.
        self.assertIn(b'DefaultDependencies=no\n', n.BOOT_TARGET_BYTES)
        for token in (b'Wants=', b'Requires=', b'[Install]', b'WantedBy=', b'Exec'):
            self.assertNotIn(token, n.BOOT_TARGET_BYTES)
        self.assertIn(b'ExecStart=\nExecStart=/usr/lib/systemd/systemd --user --unit=p0-v2-native.target\n',
                      n.PROPOSED_MANAGER_BYTES)
        self.assertNotIn(b'ExecStart=', n.DROPIN_BYTES)  # Current publisher NOT silently switched.
        for key in ('qualified', 'publicationImplemented', 'transitionImplemented', 'nativeAuthority', 'installationCertified'):
            self.assertFalse(proposal[key])

    def test_incomplete_duplicate_or_extra_properties_refuse(self):
        facts = self.facts()
        raw = b'\n'.join((k + '=' + v).encode() for k, v in facts.items())
        n.properties(raw)
        for bad in (b'Id=' + n.MANAGER.encode(), raw + b'\nId=duplicate', raw + b'\nEnvironment=FORBIDDEN'):
            with self.subTest(raw=bad), self.assertRaises(n.Refused):
                n.properties(bad)

    def test_pause_observer_never_turns_missing_pidfile_into_absence_or_signal_authority(self):
        with patch.object(n.os, 'open', side_effect=FileNotFoundError):
            with self.assertRaisesRegex(n.Refused, '^pause-metadata-unavailable$'):
                n.PauseObserver().collect()
        with patch.object(n, 'PAUSE_PROFILE', None):
            result = n.PauseObserver().collect()
        self.assertFalse(result['oldPauseClosed'])
        self.assertFalse(result['signalAuthority'])
        self.assertEqual(n.PAUSE_PROFILE['pidfile'], '/run/user/1004/libpod/tmp/pause.pid')

    def test_pause_profile_cannot_point_at_arbitrary_root_file(self):
        for path in ('/etc/shadow', '/run/user/1000/pause.pid', '/run/user/1004/../1000/pause.pid'):
            profile = dict(n.PAUSE_PROFILE, pidfile=path)
            with self.subTest(path=path), patch.object(n.os, 'open') as opened:
                with self.assertRaises(n.Refused):
                    n.PauseObserver().observe(profile)
                opened.assert_not_called()

    def test_private_source_guard_binds_hash_snapshot_and_executable_filesystem(self):
        raw, snapshot = b'SYNTHETIC_STAGED_SOURCE_ONLY', tuple(range(9))
        path = '/var/lib/UNCREATED-source08-fixture/provision-p0-v2-view.py'
        with patch.object(n, '__file__', path), patch.object(n, 'root_ancestors'), \
             patch.object(n, 'bounded', return_value=b'0 0 4294967295\n'), \
             patch.object(n, 'owned_file', return_value=(raw, snapshot)) as reader, \
             patch.object(n.os, 'statvfs', return_value=types.SimpleNamespace(f_flag=0)):
            guard = n.SelfGuard(n.sha(raw))
            guard.check()
            reader.return_value = (raw, (*snapshot[:-1], 999))
            with self.assertRaisesRegex(n.Refused, '^held-source-snapshot-changed$'):
                guard.check()
        with patch.object(n, '__file__', path), patch.object(n, 'root_ancestors'), \
             patch.object(n, 'bounded', return_value=b'0 0 4294967295\n'), \
             patch.object(n, 'owned_file', return_value=(raw, snapshot)), \
             patch.object(n.os, 'statvfs', return_value=types.SimpleNamespace(f_flag=n.os.ST_NOEXEC)):
            with self.assertRaisesRegex(n.Refused, '^source-filesystem-noexec$'):
                n.SelfGuard(n.sha(raw))

    def test_dedicated_account_requires_fixed_uid_gid_home_and_no_supplementary_membership(self):
        entry = types.SimpleNamespace(pw_uid=1004, pw_gid=1004, pw_dir='/var/lib/p0-runtime', pw_shell='/usr/sbin/nologin')
        group = types.SimpleNamespace(gr_name='p0-runtime', gr_mem=[])
        with patch.object(n.pwd, 'getpwnam', return_value=entry), patch.object(n.grp, 'getgrgid', return_value=group), \
             patch.object(n.grp, 'getgrall', return_value=[group]) as groups:
            self.assertEqual(n.runtime_account(), entry)
            groups.return_value = [group, types.SimpleNamespace(gr_mem=['p0-runtime'])]
            with self.assertRaisesRegex(n.Refused, '^dedicated-account-binding$'):
                n.runtime_account()

    def test_process_stat_parser_handles_spaces_and_closing_parentheses_in_comm(self):
        raw = ('77 (fixture ) comm) S ' + ' '.join(['1'] * 18 + ['12345', '0'])).encode()
        self.assertEqual(n.process_start(raw), 12345)

    def test_phase_vocabulary_does_not_grant_secrets_store_or_complete(self):
        record, _ = complete_fixture()
        for state in n.STATES:
            record['state'] = state
            n.seal(record)
            operations = n.phase_operations(record)
            self.assertNotIn('provision-secrets', operations)
            self.assertNotIn('native-podman', operations)
            self.assertNotIn('publish-complete', operations)
        record['state'] = 'native-view-bound'
        n.seal(record)
        self.assertIn('publish-manager-source', n.phase_operations(record))
        self.assertNotIn('explicit-manager-transition', n.phase_operations(record))

    def test_source_guard_refuses_development_tree_before_read(self):
        with patch.object(n, 'owned_file') as read:
            with self.assertRaisesRegex(n.Refused, '^private-source-location$'):
                n.SelfGuard('a' * 64)
            read.assert_not_called()


class Source08BootstrapTests(unittest.TestCase):
    def setUp(self):
        # Reuse ONLY fixture setup, no inherited/duplicated test counting.
        LedgerTests.setUp(self)
        self.source = self.root / 'source-data'
        self.source.mkdir(mode=0o711)
        self.source.chmod(0o711)
        self.fd = os.open(self.source, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, self.fd)
        self.data = n.fd_node(self.fd)
        self.prior = previous()
        self.prior['namespace'] = {k: self.data[k] for k in ('device', 'inode', 'filesystemId')}
        n.seal(self.prior)
        self.raw = n.encoded(self.prior)
        self.host = types.SimpleNamespace(prior=self.prior, previous_sha=n.sha(self.raw), raw=self.raw,
            previous_snapshot=(1, 2, 3), namespace={'device': 4, 'inode': 9}, boot=self.prior['bootId'],
            guard=types.SimpleNamespace(digest='c' * 64), check=lambda: None,
            preflight=lambda **kwargs: None, data_fd=self.fd)
        self.base = self.root / 'protected'
        self.targets = ((self.base, 0o700), (self.base / 'stack', 0o711), (self.base / 'stack/p0-v2', 0o711))
        self.host.targets = self.targets
        real_space = n.os.fstatvfs
        def fixture_space(fd):
            actual = real_space(fd)
            return types.SimpleNamespace(f_fsid=actual.f_fsid, f_bavail=2 * 1024**3, f_frsize=1)
        self.stack.enter_context(patch.object(n.os, 'fstatvfs', side_effect=fixture_space))
        self.stack.enter_context(patch.object(n, 'BASE', self.base))
        self.stack.enter_context(patch.object(n, 'STACK', self.base / 'stack'))
        self.stack.enter_context(patch.object(n, 'ANCHOR', self.base / 'stack/p0-v2'))
        self.kernel = types.SimpleNamespace(clone_anchor=lambda *a, **k: (_ for _ in ()).throw(n.Refused('synthetic-before-clone')))
        self.bootstrap = n.Bootstrap(self.host, self.store, self.kernel)

    def prepare(self):
        with self.assertRaisesRegex(n.Refused, '^synthetic-before-clone$'):
            self.bootstrap.run('transition')
        return self.store.load()

    def test_fresh_targets_are_durably_claimed_before_each_mkdir_and_umask_independent(self):
        real_mkdir, observations = n.os.mkdir, []
        def mkdir(path, *args, **kwargs):
            if path in ('protected', 'stack', 'p0-v2'):
                record = self.store.load()
                effect = record['anchor']['bootstrap']['effects'][-1]
                self.assertEqual(effect['state'], 'claimed')
                self.assertIsNone(effect['identity'])
                observations.append(effect['path'])
            return real_mkdir(path, *args, **kwargs)
        old = os.umask(0o077)
        try:
            with patch.object(n.os, 'mkdir', side_effect=mkdir):
                record = self.prepare()
        finally:
            os.umask(old)
        self.assertEqual(observations, [str(path) for path, _ in self.targets])
        self.assertEqual(record['state'], 'anchor-preclaimed')
        self.assertTrue(record['anchor']['cloneRequested'])
        self.assertIsNone(record['anchor']['preclaimedId'])
        for effect, (path, mode) in zip(record['anchor']['bootstrap']['effects'], self.targets):
            self.assertEqual(effect['state'], 'prepared')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
        self.assertEqual((self.store.base / 'previous-v2.json').read_bytes(), self.raw)

    def test_existing_matching_target_is_never_adopted_or_claimed(self):
        self.base.mkdir(mode=0o700)
        with self.assertRaisesRegex(n.Refused, '^bootstrap-target-exists$'):
            self.bootstrap.run('transition')
        self.assertIsNone(self.store.load())
        self.assertFalse((self.store.base / 'previous-v2.json').exists())

    def test_mkdir_interruption_refuses_even_if_target_absent_and_keeps_claim(self):
        real_mkdir = n.os.mkdir
        def mkdir(path, *args, **kwargs):
            if path == 'stack':
                raise OSError('SYNTHETIC_NEW_FIXTURE_MKDIR')
            return real_mkdir(path, *args, **kwargs)
        with patch.object(n.os, 'mkdir', side_effect=mkdir), self.assertRaises(OSError):
            self.bootstrap.run('transition')
        self.assertFalse((self.base / 'stack').exists())
        with self.assertRaisesRegex(n.Refused, '^mkdir-effect-review-required$'):
            self.bootstrap.run('resume')
        self.assertEqual(self.store.load()['anchor']['bootstrap']['effects'][-1]['state'], 'claimed')

    def test_requested_clone_never_replays_even_if_no_mount_id_was_published(self):
        self.prepare()
        with patch.object(n.os, 'mkdir') as mkdir:
            with self.assertRaisesRegex(n.Refused, '^detached-or-namespace-effect-review-required$'):
                self.bootstrap.run('resume')
            mkdir.assert_not_called()

    def test_prepared_before_request_checkpoint_resumes_without_any_mkdir(self):
        record = self.prepare()
        # Construct NEW fixture's durable snapshot immediately before request.
        record['state'] = 'claimed'
        record['anchor'].pop('cloneRequested')
        record['anchor'].pop('preclaimedId')
        self.store.save(n.seal(record))
        with patch.object(n.os, 'mkdir') as mkdir:
            with self.assertRaisesRegex(n.Refused, '^synthetic-before-clone$'):
                self.bootstrap.run('resume')
            mkdir.assert_not_called()
        self.assertTrue(self.store.load()['anchor']['cloneRequested'])

    def test_prepared_directory_substitution_refuses(self):
        self.prepare()
        path = self.base / 'stack/p0-v2'
        path.rename(self.base / 'stack/retained-old-fixture')
        path.mkdir(mode=0o711)
        path.chmod(0o711)
        with self.assertRaisesRegex(n.Refused, '^bootstrap-created-inode-changed$'):
            self.bootstrap.run('resume')

    def test_copied_same_byte_ledger_directory_cannot_adopt_previous_claim(self):
        self.prepare()
        active = (self.store.base / 'active.json').read_bytes()
        previous_raw = (self.store.base / 'previous-v2.json').read_bytes()
        self.store.close()
        self.store.base.rename(self.root / 'retained-original-ledger-fixture')
        self.store.base.mkdir(mode=0o700)
        for name, raw in (('active.json', active), ('previous-v2.json', previous_raw)):
            path = self.store.base / name
            path.write_bytes(raw)
            path.chmod(0o400)
        self.store.open()
        with self.assertRaisesRegex(n.Refused, '^bootstrap-record-binding$'):
            self.bootstrap.run('resume')

    def test_actual_ledger_filesystem_low_capacity_refuses_before_target_claims(self):
        with patch.object(n.os, 'fstatvfs', return_value=types.SimpleNamespace(f_bavail=1024, f_frsize=1)):
            with self.assertRaisesRegex(n.Refused, '^actual-ledger-staging-reserve$'):
                self.bootstrap.run('transition')
        self.assertFalse(self.base.exists())
        self.assertIsNone(self.store.load())

    def test_changed_source_boot_prior_snapshot_refuses_resume(self):
        self.prepare()
        for key, value in (('boot', '87654321-1234-1234-1234-123456789abc'), ('previous_snapshot', (9, 9))):
            old = getattr(self.host, key)
            setattr(self.host, key, value)
            with self.subTest(key=key), self.assertRaisesRegex(n.Refused, '^bootstrap-record-binding$'):
                self.bootstrap.run('resume')
            setattr(self.host, key, old)
        self.host.guard.digest = 'd' * 64
        with self.assertRaisesRegex(n.Refused, '^bootstrap-record-binding$'):
            self.bootstrap.run('resume')

    def test_incomplete_retention_never_replays_target_creation(self):
        self.prepare()
        (self.store.base / 'previous-v2.json').unlink()  # Exact new fixture only.
        with self.assertRaises(FileNotFoundError), patch.object(n.os, 'mkdir') as mkdir:
            self.bootstrap.run('resume')
        mkdir.assert_not_called()


class Source08KernelBackendTests(unittest.TestCase):
    def setUp(self):
        LedgerTests.setUp(self)
        self.handle = self.root / 'new-holder/namespace'
        self.stack.enter_context(patch.object(n, 'HANDLE', self.handle))
        self.kernel = n.KernelBackend.__new__(n.KernelBackend)
        self.stack.enter_context(patch.object(n, 'fd_mount_id', return_value=777))
        self.stack.enter_context(patch.object(n, 'mount_row', return_value={'id': 777}))
        self.claims = []
        self.record = {'anchor': {'result': {'parent': node(10), 'data': node(20), 'mountId': 150}}}

    def test_fresh_holder_private_mount_precedes_file_and_namespace_and_is_durably_claimed(self):
        def claim(value):
            self.claims.append(copy.deepcopy(value))
        def attach(source, target, path, preclaim, recheck):
            self.assertEqual(source, target)  # ONLY fresh holder self-clone, not DATA.
            self.assertEqual(path, self.handle.parent)
            self.assertEqual(self.claims[-1]['phase'], 'holder-clone-requested')
            self.assertFalse(self.handle.exists())
            preclaim(777)
            self.assertEqual(self.claims[-1]['phase'], 'holder-mount-preclaimed')
            recheck()
            return 777
        self.kernel.attach = attach
        def create(parent, cover, record, facts, claim, recheck):
            self.assertEqual(facts['phase'], 'handle-file-prepared')
            self.assertEqual(facts['holder']['mountId'], 777)
            self.assertEqual(stat.S_IMODE(self.handle.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(self.handle.stat().st_mode), 0o400)
            raise n.Refused('synthetic-no-fork')
        self.kernel.create_projection = create
        with self.assertRaisesRegex(n.Refused, '^synthetic-no-fork$'):
            self.kernel.persist_namespace(55, self.record, claim=claim, recheck=lambda: None)
        self.assertEqual([c['phase'] for c in self.claims], ['holder-directory-claimed', 'holder-prepared',
            'holder-clone-requested', 'holder-mount-preclaimed', 'holder-private', 'handle-file-claimed', 'handle-file-prepared'])
        self.assertTrue(self.handle.exists())  # No uncertain-effect cleanup.

    def test_existing_holder_refuses_without_claim_or_adoption(self):
        self.handle.parent.mkdir(mode=0o700)
        with self.assertRaisesRegex(n.Refused, '^namespace-holder-exists$'):
            self.kernel.persist_namespace(55, self.record, claim=self.claims.append, recheck=lambda: None)
        self.assertFalse(self.claims)
        self.assertFalse(self.handle.exists())

    def test_creator_effect_is_claimed_before_fork_and_failure_retained(self):
        def fork():
            self.assertEqual(self.claims[-1]['phase'], 'creator-claimed')
            raise n.Refused('synthetic-fork-not-executed')
        with patch.object(n.os, 'fork', side_effect=fork), self.assertRaisesRegex(n.Refused, '^synthetic-fork-not-executed$'):
            self.kernel.create_projection(55, 66, self.record, {}, self.claims.append, lambda: None)
        self.assertEqual(self.claims[-1]['phase'], 'creator-claimed')

    def test_framed_claim_ipc_exact_roundtrip_uses_only_new_unprivileged_pipe(self):
        reader, writer = os.pipe()
        try:
            expected = {'kind': 'projection-claim', 'ids': {'parent': 701, 'data': 702}}
            n.send_frame(writer, expected)
            self.assertEqual(n.receive_frame(reader), expected)
        finally:
            os.close(reader); os.close(writer)

    def test_frame_limit_refuses_before_pipe_write(self):
        with patch.object(n.os, 'write') as write:
            with self.assertRaisesRegex(n.Refused, '^worker-frame-limit$'):
                n.send_frame(-1, {'payload': 'x' * 9000})
            write.assert_not_called()


class Source08ManagerPublicationTests(unittest.TestCase):
    def setUp(self):
        Source08BootstrapTests.setUp(self)
        Source08BootstrapTests.prepare(self)
        record = self.store.load()
        record.update(state='native-view-bound', native={'fixtureOnly': True})
        record['anchor']['result'] = {'parent': n.fd_node_path(self.base / 'stack'),
            'data': n.fd_node_path(self.base / 'stack/p0-v2'), 'mountId': 150}
        record['anchor']['preclaimedId'] = 150
        self.store.save(n.seal(record))
        self.stack.enter_context(patch.object(n, 'observe_anchor_mount', return_value=record['anchor']['result']))
        self.kernel.verify_bound = lambda record: None  # Explicit mechanism-only fake.
        self.system = self.root / 'system'
        self.system.mkdir()
        self.dropin = self.system / 'user@1004.service.d/50-p0-v2-view.conf'
        self.stack.enter_context(patch.object(n, 'DROPIN', self.dropin))
        facts = Source08MetadataTests().facts()
        self.stack.enter_context(patch.object(n.MetadataObserver, 'manager', return_value={
            'facts': facts, 'profileQualified': True, 'unknownDropins': 0}))
        self.stack.enter_context(patch.object(n.MetadataObserver, 'stopped_scope', return_value={}))
        def rename(parent, source, destination):
            self.assertEqual(self.store.load()['manager']['state'], 'publish-claimed')
            self.assertFalse(self.dropin.exists())
            os.rename(source, destination, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        self.stack.enter_context(patch.object(n, 'rename_fresh', side_effect=rename))
        self.publisher = n.ManagerPublication(self.bootstrap)

    def test_literal_fresh_source_publication_does_not_reload_start_or_complete(self):
        result = self.publisher.run()
        self.assertEqual(self.dropin.read_bytes(), n.DROPIN_BYTES)
        self.assertEqual(stat.S_IMODE(self.dropin.stat().st_mode), 0o400)
        self.assertEqual(self.store.load()['manager']['state'], 'published')
        self.assertTrue(result['daemonReloadRequired'])
        self.assertFalse(result['nativeAuthority'])
        self.assertEqual(self.store.load()['state'], 'native-view-bound')

    def test_unknown_matching_directory_never_adopted(self):
        self.dropin.parent.mkdir(mode=0o700)
        with self.assertRaisesRegex(n.Refused, '^manager-directory-exists$'):
            self.publisher.run()
        self.assertIsNone(self.store.load()['manager'])

    def test_rename_interruption_reconciles_only_recorded_exact_stage_inode(self):
        with patch.object(n, 'rename_fresh', side_effect=OSError('SYNTHETIC_RENAME_BEFORE_EFFECT')):
            with self.assertRaises(OSError):
                self.publisher.run()
        record = self.store.load()
        self.assertEqual(record['manager']['state'], 'publish-claimed')
        stage = self.dropin.parent / '.p0-view-manager-publish'
        self.assertTrue(stage.exists())
        self.publisher.run()
        self.assertFalse(stage.exists())
        self.assertEqual(self.store.load()['manager']['state'], 'published')

    def test_rename_effect_then_interruption_reconciles_exact_final_inode(self):
        def rename_then_fail(parent, source, destination):
            os.rename(source, destination, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
            raise OSError('SYNTHETIC_AFTER_RENAME_BEFORE_CLAIM_PUBLICATION')
        with patch.object(n, 'rename_fresh', side_effect=rename_then_fail), self.assertRaises(OSError):
            self.publisher.run()
        self.assertTrue(self.dropin.exists())
        self.assertEqual(self.store.load()['manager']['state'], 'publish-claimed')
        self.publisher.run()
        self.assertEqual(self.store.load()['manager']['state'], 'published')

    def test_lost_inode_proof_after_source_create_never_replays_or_adopts(self):
        real_write = n.os.write
        def write(fd, raw):
            if raw == n.DROPIN_BYTES:
                raise OSError('SYNTHETIC_NEW_SOURCE_WRITE')
            return real_write(fd, raw)
        with patch.object(n.os, 'write', side_effect=write), self.assertRaises(OSError):
            self.publisher.run()
        self.assertEqual(self.store.load()['manager']['state'], 'source-claimed')
        with self.assertRaisesRegex(n.Refused, '^manager-publication-effect-review-required$'):
            self.publisher.run()
        self.assertEqual((self.dropin.parent / '.p0-view-manager-publish').read_bytes(), b'')

    def test_other_phase_refuses_before_live_kernel_or_source_effect(self):
        record = self.store.load()
        record['state'] = 'anchor-private'
        self.store.save(n.seal(record))
        self.kernel.verify_bound = lambda record: self.fail('kernel called for unauthorized phase')
        with self.assertRaisesRegex(n.Refused, '^manager-publication-phase$'):
            self.publisher.run()
        self.assertFalse(self.dropin.parent.exists())


class Source08PauseMetadataTests(unittest.TestCase):
    def setUp(self):
        from contextlib import ExitStack
        self.stack = self.enterContext(ExitStack())
        self.pid = 1313  # Synthetic only, never opened on this Host.
        self.path = Path(n.PAUSE_PROFILE['pidfile'])
        self.file = types.SimpleNamespace(st_dev=64, st_ino=44, st_mode=stat.S_IFREG | 0o600,
            st_uid=1004, st_gid=1004, st_nlink=1, st_size=5, st_mtime_ns=10, st_ctime_ns=11)
        self.executable = types.SimpleNamespace(st_dev=1, st_ino=77, st_mode=stat.S_IFREG | 0o755,
            st_uid=0, st_gid=0, st_nlink=1, st_size=30, st_mtime_ns=20, st_ctime_ns=21)
        self.status_reads, self.maps_root, self.changed_namespace, self.exited = 0, False, False, False
        self.uid_after = False
        self.closed, self.opened = [], []
        self.fd_types = {10: 'pidfile', 11: 'pidfd', 12: 'procdir', 13: 'exe', 14: 'parent', 15: 'data', 16: 'user', 17: 'mnt'}
        def opened(path, flags):
            path = str(path)
            self.opened.append(path)
            if path == str(self.path):
                return 10
            return {'/proc/1313': 12, '/proc/1313/exe': 13, '/proc/1313/root/mnt/stack': 14,
                '/proc/1313/root/mnt/stack/p0-v2': 15, '/proc/1313/ns/user': 16, '/proc/1313/ns/mnt': 17}[path]
        def fstat(fd):
            if fd == 10:
                return self.file
            if fd == 13:
                return self.executable
            return types.SimpleNamespace(st_dev=4, st_ino=900 + fd, st_mode=stat.S_IFREG | 0o444)
        def file_stat(path, **kwargs):
            if Path(path) == self.path:
                return self.file
            fd = {'/proc/1313/ns/user': 16, '/proc/1313/ns/mnt': 17}[str(path)]
            result = fstat(fd)
            if self.changed_namespace:
                return types.SimpleNamespace(st_dev=4, st_ino=result.st_ino + 1)
            return result
        def bounded(path, limit):
            path = str(path)
            if path.endswith('/stat'):
                return ('1313 (fake pause) S ' + ' '.join(['1'] * 18 + ['12345', '0'])).encode()
            if path.endswith('/status'):
                self.status_reads += 1
                uid = '1005' if self.uid_after and self.status_reads > 1 else '1004'
                return ('Uid:\t' + ' '.join([uid] * 4) + '\nGid:\t1004 1004 1004 1004\nGroups:\t1004\n'
                    'CapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\n'
                    'CapBnd:\t000001ffffffffff\nNoNewPrivs:\t0\n').encode()
            if path.endswith(('/uid_map', '/gid_map')):
                return b'0 0 1\n' if self.maps_root else b'0 1004 1\n1 300000 65536\n'
            if path.endswith('/cgroup'):
                return ('0::' + n.PAUSE_PROFILE['cgroup'] + '\n').encode()
            if path == '/proc/self/fdinfo/11':
                return b'Pid:\t1313\n'
            if path.endswith('/boot_id'):
                return previous()['bootId'].encode()
            self.fail('Unexpected synthetic metadata read: ' + path)
        owner = self
        class Poller:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def register(self, *args): pass
            def select(self, timeout): return [(1, 1)] if owner.exited else []
        for target, value in (('open', opened), ('fstat', fstat), ('stat', file_stat),
                              ('read', lambda fd, size: b'1313\n'), ('close', self.closed.append),
                              ('pidfd_open', lambda *args: 11), ('readlink', lambda path: '/usr/bin/catatonit')):
            self.stack.enter_context(patch.object(n.os, target, side_effect=value))
        self.stack.enter_context(patch.object(n, 'bounded', side_effect=bounded))
        self.stack.enter_context(patch.object(n, 'binary_snapshot', return_value={
            'sha256': n.PAUSE_PROFILE['sha256'], 'snapshot': list(n.file_snapshot(self.executable))}))
        self.stack.enter_context(patch.object(n, 'fd_node', side_effect=lambda fd:
            node(10, uid=1000, gid=1000, mode=0o2775) if fd == 14 else node(20)))
        self.stack.enter_context(patch.object(n.fcntl, 'ioctl', side_effect=lambda fd, op: 0x10000000 if fd == 16 else 0x20000))
        self.stack.enter_context(patch.object(n.selectors, 'DefaultSelector', Poller))

    def test_actual_style_userns_capabilities_are_metadata_not_host_root_or_signal_permit(self):
        result = n.PauseObserver().collect()
        self.assertTrue(result['available'])
        self.assertEqual(result['capabilities']['CapEff'], '000001ffffffffff')
        self.assertFalse(result['signalAuthority'])
        self.assertFalse(result['oldPauseClosed'])
        self.assertIsNone(result['emptyContainerReceipt'])
        self.assertEqual(result['view']['parent']['uid'], 1000)  # unsafe old view observed, not blessed.
        self.assertEqual(len(self.closed), 8)
        self.assertEqual(self.status_reads, 2)
        self.assertNotIn('/proc/1313/environ', self.opened)

    def test_namespace_change_refuses_and_closes_all_pinned_metadata_fds(self):
        self.changed_namespace = True
        with self.assertRaisesRegex(n.Refused, '^pause-namespace-changed$'):
            n.PauseObserver().collect()
        self.assertEqual(len(self.closed), 8)

    def test_credentials_changed_during_observation_refuse(self):
        self.uid_after = True
        with self.assertRaisesRegex(n.Refused, '^pause-observation-changed$'):
            n.PauseObserver().collect()

    def test_exited_pidfd_never_becomes_process_or_signal_authority(self):
        self.exited = True
        with self.assertRaisesRegex(n.Refused, '^pause-process-exited$'):
            n.PauseObserver().collect()

    def test_host_root_mapping_refuses_before_namespace_authority(self):
        self.maps_root = True
        with self.assertRaisesRegex(n.Refused, '^rootless-host-root-mapped$'):
            n.PauseObserver().collect()


class Source08ActorSourceTests(unittest.TestCase):
    def setUp(self):
        from contextlib import ExitStack
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix='.p0-actor-source08-', dir=Path.home())))
        self.stack = self.enterContext(ExitStack())
        self.config = self.root / '.config/containers'
        self.units = self.config / 'systemd'
        self.units.mkdir(parents=True, mode=0o700)
        storage = self.config / 'storage.conf'
        storage.write_bytes(n.STORAGE_BYTES)
        storage.chmod(0o600)
        self.stack.enter_context(patch.object(n, 'RUNTIME_HOME', self.root))
        self.stack.enter_context(patch.object(n, 'runtime_account'))
        self.stack.enter_context(patch.object(n, 'actor_directory', side_effect=lambda p: os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)))
        real_stat, real_fstat = os.stat, os.fstat
        def mapped(value):
            fields = {k: getattr(value, k) for k in dir(value) if k.startswith('st_')}
            fields.update(st_uid=1004 if stat.S_ISREG(value.st_mode) else 0,
                          st_gid=1004 if stat.S_ISREG(value.st_mode) else 0)
            return types.SimpleNamespace(**fields)
        self.stack.enter_context(patch.object(n.os, 'stat', side_effect=lambda *a, **kw: mapped(real_stat(*a, **kw))))
        self.stack.enter_context(patch.object(n.os, 'fstat', side_effect=lambda fd: mapped(real_fstat(fd))))
        class Entries:
            def __init__(inner, fd): inner.fd = fd
            def __enter__(inner):
                return iter([types.SimpleNamespace(name=name, stat=lambda *, follow_symlinks=False, name=name:
                    mapped(real_stat(name, dir_fd=inner.fd, follow_symlinks=follow_symlinks))) for name in os.listdir(inner.fd)])
            def __exit__(inner, *args): pass
        self.stack.enter_context(patch.object(n.os, 'scandir', Entries))

    def test_fixed_storage_bytes_and_quadlet_hashes_are_metadata_not_any_kind_of_absence(self):
        source = self.units / 'p0-fixture.container'
        source.write_bytes(b'[Container]\nImage=fixture@sha256:' + b'a' * 64 + b'\n[Service]\nRestart=on-failure\n')
        source.chmod(0o600)  # This NEW fixture's declared source custody.
        with patch.object(n, 'metadata_call', side_effect=AssertionError('NO_NATIVE_CALL')):
            report = n.ActorSourceObserver().collect()
        self.assertEqual(report['storage']['sha256'], n.sha(n.STORAGE_BYTES))
        self.assertEqual(len(report['quadlets']['files']), 1)
        self.assertFalse(report['quadlets']['files'][0]['installReplay'])
        self.assertTrue(report['quadlets']['files'][0]['requiresEveryNativeLifecycleGuard'])
        for key in ('runningKernelTasksCertifiedAbsent', 'stoppedDatabaseObjectsCertifiedAbsent',
                    'approvedProtectedViewUnshareProbe', 'oldPauseReleaseAuthorized'):
            self.assertFalse(report[key])
        self.assertFalse(report['quadlets']['frozenSupplyCompared'])
        self.assertFalse(report['quadlets']['bootGraphCertified'])

    def test_install_replay_is_conservative_and_unknown_authored_files_not_read(self):
        (self.units / 'p0-fixture.container').write_bytes(b'[Container]\nImage=fixture\n[Install]\nWantedBy=default.target\n')
        (self.units / 'p0-fixture.container').chmod(0o600)
        (self.units / 'authored.txt').write_bytes(b'NEW_TEST_FIXTURE_NOT_TO_BE_READ')
        (self.units / 'p0-foreign.volume').symlink_to(self.units / 'authored.txt')
        report = n.ActorSourceObserver().quadlets()
        self.assertTrue(report['files'][0]['installReplay'])
        self.assertEqual(report['unknownEntries'], 1)
        self.assertEqual(report['symlinks'], 1)
        self.assertEqual(len(report['files']), 1)

    def test_file_changed_after_hash_refuses_before_metadata_report(self):
        path = self.units / 'p0-fixture.container'
        path.write_bytes(b'[Container]\nImage=fixture\n')
        path.chmod(0o600)
        original = n.install_replay
        def change(raw):
            result = original(raw)
            path.write_bytes(raw + b'# NEW_CHANGED_FIXTURE\n')
            return result
        with patch.object(n, 'install_replay', side_effect=change):
            with self.assertRaisesRegex(n.Refused, '^actor-quadlet-source-changed$'):
                n.ActorSourceObserver().quadlets()

    def test_storage_path_same_byte_inode_replacement_refuses(self):
        original = n.actor_directory
        calls = []
        def reopen(path):
            calls.append(path)
            if len(calls) == 2:
                stage = self.config / 'new-storage-fixture'
                stage.write_bytes(n.STORAGE_BYTES)
                stage.chmod(0o600)
                os.replace(stage, self.config / 'storage.conf')
            return original(path)
        with patch.object(n, 'actor_directory', side_effect=reopen):
            with self.assertRaisesRegex(n.Refused, '^actor-storage-source-changed$'):
                n.ActorSourceObserver().storage()

    def test_missing_source_directory_does_not_certify_absence(self):
        self.units.rmdir()  # Exact NEW empty fixture only.
        report = n.ActorSourceObserver().quadlets()
        self.assertFalse(report['available'])
        self.assertFalse(report['absenceCertified'])
        self.assertFalse(report['nativeAuthority'])

    def test_changed_storage_graphroot_refuses_without_native_call(self):
        path = self.config / 'storage.conf'
        path.write_bytes(n.STORAGE_BYTES.replace(b'rootless/engine', b'rootless/FOREIGN'))
        with self.assertRaises(n.Refused), patch.object(n, 'metadata_call', side_effect=AssertionError('NO_NATIVE_CALL')):
            n.ActorSourceObserver().storage()

    def test_user_namespace_root_is_not_host_root_bootstrap_authority(self):
        for raw in (b'0 1000 1\n', b'0 0 1\n', b'0 0 4294967295\n1 1 1\n'):
            with self.subTest(raw=raw), patch.object(n, 'bounded', return_value=raw):
                with self.assertRaisesRegex(n.Refused, '^host-initial-user-namespace-required$'):
                    n.initial_host_user_namespace()


if __name__ == '__main__':
    unittest.main()
