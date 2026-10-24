#!/usr/bin/env python3
"""SOURCE/TEMP-FD MODEL ONLY: genuine seven-domain producers and recovery owner.

Real projector/copier/unit publishers/prepared/rootful observers and dual Root
journal writes. Numerical NSS/ACL/mount/FD9/boot/process/reserve and public Ops
transport/snapshot facts are modeled. Fake age is explicitly NOT cryptography
or installed/consistent application recovery evidence. No host operations.
"""
import argparse
import copy
import importlib.util
import json
import os
import struct
from pathlib import Path
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

BASE = Path(__file__).absolute().parents[1]
def load(name, file):
    spec = importlib.util.spec_from_file_location(name, BASE / file)
    module = importlib.util.module_from_spec(spec)
    exec(compile((BASE / file).read_bytes(), str(BASE / file), 'exec'), module.__dict__)
    return module
f = load('native_recovery_real_fixture', 'scripts/test-native-runtime-env-units.py')
n = load('native_recovery_tested', 'runtime-generator/podman-ops/native-recovery-owner.py')
old = load('native_recovery_fake_age_fixture', 'scripts/test-host-recovery.py')
a = load('native_recovery_public_ops', 'scripts/lib/stackctl-operations.py')
u, p, h = f.u, f.p, n.h
PROCESS_VIEWS = n.process_views


class Native(f.Units):
    def emit(self, release, ir, metadata):
        if release == self.release:
            ir.setdefault('volumes', {})['recovery_db'] = dict(hostPath=str(self.scope / 'recovery-db'))
            ir['services']['keycloak'] = dict(placement='rootful', lifecycle='daemon', image='sha256:' + 'e' * 64)
            ir['services']['postgres'] = dict(placement='rootful', lifecycle='daemon', image='sha256:' + 'f' * 64,
                volumes=['recovery_db:/var/lib/postgresql/data'])
        super().emit(release, ir, metadata)
        if release == self.release and 'root_private_marker_gid1000_mask0' in self._testMethodName:
            # Initialize the real temp marker BEFORE genuine producers seal any
            # source, not an after-seal inode/ACL rebase.
            undefined = 0xffffffff
            acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *entry) for entry in (
                (1, 6, undefined), (2, 7, 1000), (4, 7, undefined), (16, 0, undefined), (32, 0, undefined)))
            marker = self.scope / h.storage.MARKER
            os.setxattr(marker, 'system.posix_acl_access', acl)
            self.acls[self.key(marker)] = (acl, b''); self.set_owner(marker, 0, 1000)

    def setUp(self):
        super().setUp()
        self.run_units()
        self.running_intent['phase'] = 'active'; self.running_intent['steps'] = list(h.journal.PHASES[:5])
        for row in self.rows:
            state = Path(row['stateRoot']); (state / 'current').symlink_to(state / 'releases' / self.release.name)
        (self.install / 'current').symlink_to(self.release)
        self.write_records(self.running_intent)
        self.mkdir(self.scope / 'recovery-db'); (self.scope / 'recovery-db').chmod(0o700)
        self.put(self.scope / 'recovery-db/identity.db', b'synthetic identity database')
        self.mkdir(self.base / 'archives'); self.mkdir(self.base / 'keys'); self.mkdir(self.base / 'bin')
        self.archive = self.base / 'archives/snapshot.age'; self.identity_key = self.base / 'keys/identity'
        self.put(self.identity_key, b'fixture-key'); self.fake_age = self.base / 'bin/FAKE-AGE-NOT-CRYPTO'
        self.put(self.fake_age, old.FAKE_AGE.encode()); self.fake_age.chmod(0o700)
        self.plans = []
        inventory = u.n.inventory(self.release)
        for role, entry in inventory.items():
            units = {}
            for relative, seal in entry['files'].items():
                path = u.n.destination(role, entry, relative)
                units[seal['unit']] = dict(sourcePath=str(path), sha256=seal['sha256'], lifecycle='target', generated=False)
            uid = entry['uid']; configuration = {}
            if uid:
                row = next(r for r in self.rows if r['uid'] == uid)
                home = self.host / 'home' / row['user']
                bodies = {'storage.conf': ('[storage]\ndriver = "overlay"\ngraphroot = ' + json.dumps(row['graphRoot']) + '\n').encode(),
                    'containers.conf': b'[network]\ndefault_rootless_network_cmd = "pasta"\npasta_options = ["--map-host-loopback", "169.254.1.2"]\n'}
                for name, body in bodies.items():
                    path = home / '.config/containers' / name; self.put(path, body)
                    self.set_owner(path, uid, self.accounts[row['user']].pw_gid)
                    configuration[str(path)] = h.sha(body)
            self.plans.append(dict(role=role, uid=uid, units=units, configuration=configuration,
                offlineManagerStopped=bool(uid), command=['MODELED-SYSTEMCTL', role]))
        self.ops = ModuleType('modeled_public_ops_transport')
        self.ops.__file__ = str(self.base / 'public-operations.py')
        self.ops._recovery_compiled_source_sha256 = n.OPERATIONS_SHA256
        self.put(Path(self.ops.__file__), (BASE / 'scripts/lib/stackctl-operations.py').read_bytes())
        def body(path, *args, **kwargs):
            if path == Path('/proc/sys/kernel/random/boot_id'): return b'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n'
            if path in (Path('/etc/subuid'), Path('/etc/subgid')):
                return ''.join(f'{r["user"]}:{2883584 + (r["uid"] - 780) * 65536}:65536\n' for r in self.rows).encode()
            return h.read_file(path, private=kwargs.get('private', False))
        self.ops.body = body; self.ops.load = lambda path: h.strict(body(path))
        self.ops.journal_module = lambda: h.journal
        self.ops.snapshot = self.snapshot
        self.ops.runtime_api = lambda release: u
        self.ops.boot_identity = lambda: body(Path('/proc/sys/kernel/random/boot_id')).decode().strip()
        self.ops.stopped = a.stopped; self.ops.offline_manager = a.offline_manager
        self.manager = dict(ActiveState='inactive', SubState='dead', MainPID='0', Job='', Result='success', ControlGroup='')
        self.ops.manager_state = lambda uid: dict(self.manager)
        self.ops.no_actor_logins = lambda uid: a.no_actor_logins(uid)
        self.ops.offline_boot_units = lambda plan, journal: a.offline_boot_units(plan, journal)
        def run(command):
            if 'list-sessions' in command: return '[]'
            if 'list-unit-files' in command: return ''
            unit = command[2]
            return f'Id={unit}\nLoadState=not-found\nActiveState=inactive\nMainPID=0\nJob=\nUnitFileState=not-found\nFragmentPath=\nSourcePath=\nDropInPaths=\nNames=\n'
        self.ops.run = run; patch.object(a, 'run', new=run).start()
        patch.object(h, 'HOME_ROOT', self.host / 'home').start()
        patch.object(h, 'mount_points', return_value=set()).start()
        patch.object(h, 'mount_id', return_value=91).start()
        patch.object(h.storage, 'authority', return_value=(self.scope, self.operator, self.marker)).start()
        patch.object(h.storage, 'marker', side_effect=lambda scope, marker: self.assertEqual(marker, self.marker)).start()
        patch.object(h.journal, 'standalone_binding', return_value=self.marker).start()
        patch.object(h.journal, 'verify_quarantined', side_effect=lambda release: self.assertEqual(release, self.release)).start()
        real_api_load = u.load
        patch.object(u, 'load', side_effect=lambda name, filename: f.r if filename == 'native-rootful-env-owner.py' else real_api_load(name, filename)).start()
        patch.object(n, 'process_views', return_value=[]).start()
        statvfs = os.statvfs
        patch.object(os, 'statvfs', side_effect=lambda path: SimpleNamespace(f_bavail=1000 * n.GIB, f_frsize=1, f_favail=100000)).start()
        read_text = Path.read_text
        def text(path, *args, **kwargs):
            if path == Path('/proc/meminfo'): return 'MemAvailable: 64000000 kB\n'
            return read_text(path, *args, **kwargs)
        patch.object(Path, 'read_text', new=text).start()
        real_path = Path
        def namespace(path):
            if str(path) == '/usr/bin/age': return self.fake_age
            value = real_path(path)
            if value == real_path('/run') or value.is_relative_to('/run'): return self.host / value.relative_to('/')
            return value
        self.namespace = namespace
        patch.object(n, 'Path', side_effect=namespace).start()
        opened = os.open
        def open_fd(path, flags, mode=0o777, *, dir_fd=None):
            fd = opened(path, flags, mode, dir_fd=dir_fd)
            # Backend's no-follow O_PATH reopens are the SAME real temp inode;
            # preserve their kernel-resolved location in the numerical model.
            self.fd_paths[fd] = Path(os.readlink('/proc/self/fd/' + str(fd)))
            return fd
        patch.object(os, 'open', new=open_fd).start()
        def chown(path, uid, gid, **kwargs):
            value = Path(path)
            if value.is_relative_to('/proc/self/fd'):
                parts = value.parts; value = self.fd_paths[int(parts[4])].joinpath(*parts[5:])
            self.assertTrue(value.is_relative_to(self.base))
            self.set_owner(value, uid, gid)
        patch.object(os, 'chown', new=chown).start()
        self.lease = None
        self.addCleanup(self.close_lease)

    def snapshot(self, root, journal):
        intent = h.strict((self.install / '.install-intent.json').read_bytes())
        self.assertEqual((self.install / '.install-intent.json').read_bytes(), (self.release / 'installation-receipt.json').read_bytes())
        proof = dict(selectedRelease=self.release.name, intentSha256=h.sha((self.install / '.install-intent.json').read_bytes()),
            receiptSha256=h.sha((self.release / 'installation-receipt.json').read_bytes()),
            planSha256=h.sha(h.canonical(self.plans)), markerSha256=h.sha((self.scope / h.storage.MARKER).read_bytes()))
        observed = [{name: dict(ActiveState='inactive', Job='', UnitFileState='disabled') for name in plan['units']} for plan in self.plans]
        return self.release, intent, proof, self.plans, observed

    def close_lease(self):
        if self.lease: self.lease.close()

    def produce(self, operation=None):
        operation = operation or dict(kind='backup', archive=str(self.archive), recipient='age1' + 'q' * 58)
        expected = h.sha((self.install / '.install-intent.json').read_bytes())
        # Real journal producer + real typed owner. Only reuse the loaded
        # identical owner module to share this fixture's numerical kernel model.
        with patch.object(h.journal, 'native_recovery_owner', return_value=n):
            self.lease = h.journal.prepare_native_recovery(self.install, expected, operation, self.ops)
        return self.lease

    def test_real_seven_role_source_custody_and_dual_records(self):
        lease = self.produce()
        self.assertEqual(len(lease.custody['actors']), 7)
        self.assertEqual(len(lease.custody['configurationRoots']), 14)
        self.assertEqual(h.journal.read(self.install / '.install-intent.json'), h.journal.read(self.release / 'installation-receipt.json'))
        self.assertTrue(lease.custody['native']['immutableReferencesOnly'])
        self.assertFalse(lease.used)
        lease.guard()

    def test_root_private_marker_gid1000_mask0_acl_backup_preserves_reference(self):
        marker = self.scope / h.storage.MARKER
        acl = os.getxattr(marker, 'system.posix_acl_access')
        before = (marker.stat().st_dev, marker.stat().st_ino); body = marker.read_bytes()
        result = n.execute(self.produce())
        self.assertTrue(result['encrypted']); self.assertFalse(result['installedAcceptance'])
        self.assertEqual((marker.stat().st_dev, marker.stat().st_ino), before)
        self.assertEqual(marker.read_bytes(), body)
        self.assertEqual(os.getxattr(marker, 'system.posix_acl_access'), acl)
        self.assertEqual(marker.stat().st_gid, 1000)

    def test_json_and_reused_or_unpublished_lease_never_execute(self):
        with self.assertRaises(ValueError): n.execute({'approved': True})
        lease = self.produce(); lease.used = True
        with self.assertRaises(ValueError): n.execute(lease)

    def test_source_and_manager_drift_revoke_genuine_lease(self):
        lease = self.produce(); self.manager['ActiveState'] = 'active'
        with self.assertRaises(ValueError): lease.guard()
        self.manager['ActiveState'] = 'inactive'
        plan = next(plan for plan in self.plans if plan['configuration'])
        path = Path(next(iter(plan['configuration']))); body = path.read_bytes()
        path.rename(self.base / 'retained-original-account-config'); self.put(path, body)
        actor = next(row for row in self.rows if row['uid'] == plan['uid'])
        self.set_owner(path, actor['uid'], self.accounts[actor['user']].pw_gid)
        with self.assertRaisesRegex(ValueError, 'account-config source inode'): lease.guard()
        (self.release / 'runtime/stack.env').write_bytes(b'DOMAIN=drift\n')
        with self.assertRaises(ValueError): lease.guard()

    def test_fake_age_native_roundtrip_keeps_all_reference_inodes(self):
        lease = self.produce()
        references = [self.release / 'runtime/stack.env'] + [Path(c['path']) for c in lease.custody['configurationRoots']]
        before = {str(path): p.identity(path.stat()) for path in references}
        result = n.execute(lease)
        self.assertTrue(result['encrypted']); self.assertFalse(result['installedAcceptance'])
        (self.scope / 'recovery-db/identity.db').write_bytes(b'later synthetic state')
        self.produce(dict(kind='restore', archive=str(self.archive), archiveSha256=result['archiveSha256'], identityFile=str(self.identity_key)))
        restored = n.execute(self.lease)
        self.assertTrue(restored['restored'])
        self.assertEqual((self.scope / 'recovery-db/identity.db').read_bytes(), b'synthetic identity database')
        self.assertEqual(before, {str(path): p.identity(path.stat()) for path in references})

    def test_operation_seal_and_expiry_refuse_before_backend(self):
        lease = self.produce(); lease.operation['archive'] = str(self.base / 'different.age')
        with self.assertRaisesRegex(ValueError, 'operation changed'): n.execute(lease)
        lease.operation['archive'] = str(self.archive); lease.until = 0
        with self.assertRaisesRegex(ValueError, 'expired'): n.execute(lease)
        self.assertFalse(self.archive.exists())

    def test_fake_age_wrong_key_and_tamper_preserve_native_data(self):
        result = n.execute(self.produce())
        original = (self.scope / 'recovery-db/identity.db').read_bytes()
        operation = dict(kind='restore', archive=str(self.archive), archiveSha256=result['archiveSha256'], identityFile=str(self.identity_key))
        self.identity_key.write_bytes(b'wrong-fixture-key')
        with self.assertRaises(ValueError): n.execute(self.produce(operation))
        self.assertEqual((self.scope / 'recovery-db/identity.db').read_bytes(), original)
        self.identity_key.write_bytes(b'fixture-key')
        data = self.archive.read_bytes(); self.archive.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
        operation['archiveSha256'] = h.sha(self.archive.read_bytes())
        with self.assertRaises(ValueError): n.execute(self.produce(operation))
        self.assertEqual((self.scope / 'recovery-db/identity.db').read_bytes(), original)

    def test_interrupted_native_restore_requires_originals_recovery_cas(self):
        result = n.execute(self.produce()); db = self.scope / 'recovery-db'
        (db / 'identity.db').write_bytes(b'current-displaced-original')
        identity = (db.stat().st_dev, db.stat().st_ino); swap = n.h.Backend.swap
        def crash(backend, source, destination):
            if Path(source).name == 'new' and Path(destination) == db:
                raise OSError('synthetic interruption after original data retention')
            return swap(backend, source, destination)
        with patch.object(n.h.Backend, 'swap', new=crash), patch.object(n.h.Backend, 'rollback', side_effect=OSError('synthetic stopped process death')):
            with self.assertRaises(OSError):
                n.execute(self.produce(dict(kind='restore', archive=str(self.archive), archiveSha256=result['archiveSha256'], identityFile=str(self.identity_key))))
        self.assertFalse(db.exists())
        pending = self.install / '.host-recovery/intent.json'; digest = n.h.file_sha(pending)
        with self.assertRaises(ValueError):
            self.produce(dict(kind='recover-originals', recoveryJournalSha256='0' * 64))
        self.assertEqual(n.h.file_sha(pending), digest)
        result = n.execute(self.produce(dict(kind='recover-originals', recoveryJournalSha256=digest)))
        self.assertTrue(result['originalsRestored']); self.assertFalse(result['restart'])
        self.assertEqual((db.stat().st_dev, db.stat().st_ino), identity)
        self.assertEqual((db / 'identity.db').read_bytes(), b'current-displaced-original')

    def test_real_process_parser_models_own_mapped_and_writable_fd_refusals(self):
        lease = self.produce(); proc = self.base / 'modeled-proc'; pid = proc / '123'
        self.mkdir(pid / 'fdinfo'); self.mkdir(pid / 'fd')
        self.put(pid / 'maps', b'')
        self.put(pid / 'fdinfo/3', b'flags:\t0100002\n')
        (pid / 'fd/3').symlink_to(self.scope / 'recovery-db/identity.db')
        with patch.object(n, 'process_views', new=PROCESS_VIEWS), \
             patch.object(n, 'Path', side_effect=lambda path: proc if str(path) == '/proc' else self.namespace(path)):
            self.put(pid / 'status', b'Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\n')
            with self.assertRaisesRegex(ValueError, 'writable FD'): lease.guard()
            self.put(pid / 'fdinfo/3', b'flags:\t0100000\n')
            for label, value in (('Uid', lease.actors[0]['uid']), ('Uid', lease.actors[0]['start']),
                                 ('Gid', lease.actors[0]['gid']), ('Gid', lease.actors[0]['start'])):
                values = {'Uid':1000, 'Gid':1000}; values[label] = value
                self.put(pid / 'status', ''.join(key + ':\t' + ' '.join([str(val)] * 4) + '\n' for key, val in values.items()).encode())
                with self.assertRaisesRegex(ValueError, 'own/mapped'): lease.guard()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    select = parser.add_mutually_exclusive_group()
    select.add_argument('--case', choices=[name for name in Native.__dict__ if name.startswith('test_')])
    select.add_argument('--group', type=int, choices=(1, 2, 3))
    args = parser.parse_args()
    names = [args.case] if args.case else [name for name in Native.__dict__ if name.startswith('test_')]
    if args.group: names = [name for index, name in enumerate(names) if index % 3 == args.group - 1]
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Native(name) for name in names))
    raise SystemExit(not result.wasSuccessful())
