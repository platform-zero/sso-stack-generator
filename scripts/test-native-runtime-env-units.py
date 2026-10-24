#!/usr/bin/env python3
"""Real temp-FD restore/unit/Root-copy-custody integration, not installed proof.

Real canonical seven-role projector/copier/verifier + selected file producer +
rootful producer run. Only numeric UID/GID/ACL/mount/NSS/lock/stopped/tmpfs/boot
observations are modelled. No real chown or subprocess/native/host queries.
"""
import contextlib
import copy
import importlib.util
import os
from pathlib import Path
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


f = load('runtime_env_unit_fixture', BASE / 'scripts/test-native-install-files.py')
u = load('runtime_env_units_tested', BASE / 'runtime-generator/podman-ops/native-runtime-env-units.py')
r = load('runtime_env_rootful_producer', BASE / 'runtime-generator/podman-ops/native-rootful-env-owner.py')
# Alias identical owning implementations solely to share the fixture's kernel
# identity model. No source/custody/permission/projection success shim.
u.m, u.v, u.o, u.p, u.n = f.m, f.m.v, f.m.o, f.m.p, f.m.native
u.require, u.Refused = f.m.require, f.m.Refused
u.Session.actor_directories = u.PreparedUnits.actor_directories = u.RunningSeal.actor_directories = f.m.Session.actor_directories
u.Session.open_host = u.PreparedUnits.open_host = u.RunningSeal.open_host = f.m.Session.open_host
u.Session.absent, u.Session.verify_overrides = f.m.Session.absent, f.m.Session.verify_overrides
r.m, r.v, r.o, r.p = f.m, f.m.v, f.m.o, f.m.p
r.require, r.Refused = u.require, u.Refused
p = u.p


class Units(f.Files):
    def emit(self, release, ir, metadata):
        if 'rootful_empty' not in self._testMethodName:
            ir['services']['edge']['environment'] = {'DOMAIN': '${DOMAIN}'}
        if 'mixed' in self._testMethodName:
            ir['services']['edge-second'] = dict(placement='rootful', lifecycle='daemon', image='sha256:' + 'd' * 64,
                                                 environment={'DOMAIN': '${DOMAIN}'})
        super().emit(release, ir, metadata)

    def setUp(self):
        super().setUp()
        patch.object(u, 'HOST', self.host).start()
        self.addCleanup(self.close_unit_sessions)
        self.as_actor = None; self.restore_events = []
        self.install_plain_kernel_model()
        ns = u._runtime
        self.runtime_original_child = ns['child']
        def child(parent, name, flags, no_xdev=True):
            fd = self.runtime_original_child(parent, name, flags, no_xdev)
            self.fd_paths[fd] = self.fd_paths[parent] / name
            self.restore_events.append((self.fd_paths[fd], flags, no_xdev))
            return fd
        patch.dict(ns, child=child, HOST=self.host, _mount=lambda fd: 91, _tmpfs=lambda fd: True,
                   _acl=lambda fd, name: p.acl_bytes(fd, name), _boot=lambda: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                   _uid=lambda: 0 if self.as_actor is None else self.as_actor[0],
                   _gid=lambda: 0 if self.as_actor is None else self.as_actor[1]).start()
        # Emulate the creator's UID/GID on NEW leaves, never privileged chown.
        opened, mkdir = os.open, os.mkdir
        def create(path, flags, mode=0o777, *, dir_fd=None):
            fd = opened(path, flags, mode, dir_fd=dir_fd)
            if flags & os.O_CREAT and self.as_actor is not None:
                actual = self.raw_fstat(fd); self.virtual[actual.st_dev, actual.st_ino] = self.as_actor
            return fd
        def created(path, mode=0o777, *, dir_fd=None):
            mkdir(path, mode, dir_fd=dir_fd)
            if self.as_actor is not None:
                actual = Path(path) if dir_fd is None else self.fd_paths[dir_fd] / path
                self.set_owner(actual, *self.as_actor)
        patch.object(os, 'open', new=create).start()
        patch.object(os, 'mkdir', new=created).start()
        self.mkdir(self.host / 'run/user'); (self.host / 'run/user').chmod(0o755)
        (self.host / 'run').chmod(0o755)
        for row in self.rows:
            anchor = self.host / 'run/user' / str(row['uid']); self.mkdir(anchor)
            self.set_owner(anchor, row['uid'], self.accounts[row['user']].pw_gid)
        def query(command, **kwargs):
            self.assertEqual(command[:2], ['systemctl', 'show'])
            self.assertIn(command[2], ('webservices.target', u.UNIT))
            props = dict(Id=command[2], Names=command[2], LoadState='not-found', ActiveState='inactive',
                         MainPID='0', Job='', DropInPaths='', SourcePath='', FragmentPath='')
            return SimpleNamespace(returncode=0, stdout='\n'.join(key + '=' + value for key, value in props.items()))
        patch.object(subprocess, 'run', new=query).start()
        # Real selected-unit-file producer, then real rootful environment copy.
        if 'legacy_adjunct' in self._testMethodName:
            self.previous_source('retired-failed')
        selected = self.run_files()
        self.prior = dict(self.new_intent, nativeUnitFiles=selected); self.write_records(self.prior)
        custody = r.prepare_custody(self.install, self.release, self.prior)
        new = dict(self.prior, rootfulEnvCustody=custody); self.write_records(new)
        rootful = r.copy_environment(self.install, self.release, new)
        self.prior = dict(new, rootfulEnvironmentStoreHandoff=rootful); self.write_records(self.prior)
        self.mutations.clear()

    def install_plain_kernel_model(self):
        # Existing fixture MagicMock call histories would retain hundreds of
        # thousands of per-inode observations in bounded resource scopes. Preserve
        # exactly the same numerical model with plain functions, not success
        # shims or production permission changes.
        test = self
        class Modeled:
            def __init__(self, actual):
                self.actual = actual
                self.st_uid, self.st_gid = test.virtual.get((actual.st_dev, actual.st_ino), (0, 0))
                self.st_mode = actual.st_mode
                if (actual.st_dev, actual.st_ino) in test.ancestor_ids:
                    self.st_mode = stat.S_IFDIR | 0o755
                    self.st_size = self.st_mtime_ns = self.st_ctime_ns = 0; self.st_nlink = 2
            def __getattr__(self, name): return getattr(self.actual, name)
        def opened(path, flags, mode=0o777, *, dir_fd=None):
            fd = self.raw_open(path, flags, mode, dir_fd=dir_fd)
            value = Path(os.fsdecode(path))
            self.fd_paths[fd] = value if value.is_absolute() else self.fd_paths.get(dir_fd, Path.cwd()) / value
            if flags & os.O_CREAT and flags & os.O_EXCL:
                info = self.raw_fstat(fd); self.virtual[info.st_dev, info.st_ino] = (0, 0)
            return fd
        def duplicated(fd):
            result = self.raw_dup(fd); self.fd_paths[result] = self.fd_paths[fd]; return result
        def chown(fd, uid, gid):
            self.assertTrue(self.fd_paths[fd].is_relative_to(self.base))
            info = self.raw_fstat(fd); self.virtual[info.st_dev, info.st_ino] = uid, gid
            self.mutations.append((self.fd_paths[fd], uid, gid))
        def chmod(fd, mode):
            self.assertTrue(self.fd_paths[fd].is_relative_to(self.base)); self.raw_chmod(fd, mode)
        def acl(fd, name):
            info = self.raw_fstat(fd); row = self.acls.get((info.st_dev, info.st_ino), (b'', b''))
            return row[0] if name == 'system.posix_acl_access' else row[1]
        raw_child = load('exact_env_kernel_open', BASE / 'runtime-generator/podman-ops/project-domain-runtime.py').child_open
        def child(parent, name, flags):
            fd = raw_child(parent, name, flags); self.fd_paths[fd] = self.fd_paths[parent] / name; return fd
        replacements = [(os, 'fstat', lambda fd: Modeled(self.raw_fstat(fd))),
            (os, 'stat', lambda *a, **kw: Modeled(self.raw_stat(*a, **kw))),
            (os, 'lstat', lambda *a, **kw: Modeled(self.raw_lstat(*a, **kw))),
            (os, 'open', opened), (os, 'dup', duplicated), (os, 'fchown', chown), (os, 'fchmod', chmod),
            (os, 'geteuid', lambda: 0), (p, 'acl_bytes', acl), (p, 'mount_id', lambda fd: 91),
            (p, 'child_open', child), (f.m.o, 'lock_held', lambda root: None), (f.m.o, 'inactive', lambda release, domain: None),
            (f.m.o.storage, 'authority', lambda release: (self.scope, self.operator, self.marker)),
            (f.m.o.storage, 'namespace_root_id', lambda user: 2883584 + (self.accounts[user].pw_uid - 780) * 65536),
            (f.m.o.pwd, 'getpwnam', lambda user: self.accounts[user]),
            (f.m.o.pwd, 'getpwuid', lambda uid: next(a for a in self.accounts.values() if a.pw_uid == uid)),
            (f.m.o.pwd, 'getpwall', lambda: list(self.accounts.values())),
            (f.m.o.grp, 'getgrnam', lambda name: self.groups[name]),
            (f.m.o.grp, 'getgrgid', lambda gid: next(g for g in self.groups.values() if g.gr_gid == gid))]
        for obj, name, callback in replacements: patch.object(obj, name, new=callback).start()
        for obj, name in ((f.m.native, 'directory_policy'), (f.m.native, 'destination')):
            patch.object(obj, name, new=getattr(obj, name).side_effect).start()

    def close_unit_sessions(self):
        for module in (u, r):
            for session in module._sessions.values(): session.close()
            module._sessions.clear()

    def prepare_units(self):
        self.unit_custody = u.prepare_custody(self.install, self.release, self.prior)
        return self.unit_custody

    def seal_units(self):
        self.units_intent = dict(self.prior, nativeRuntimeEnvUnitCustody=self.unit_custody)
        self.write_records(self.units_intent)

    def publish_units(self):
        return u.publish(self.install, self.release, self.units_intent)

    def run_units(self):
        self.prepare_units(); self.seal_units(); proof = self.publish_units()
        self.running_intent = dict(self.units_intent, nativeRuntimeEnvUnits=proof)
        self.write_records(self.running_intent)
        return proof

    @contextlib.contextmanager
    def role(self, name):
        spec = self.unit_custody['roles'][name]
        old = self.as_actor; self.as_actor = spec['uid'], spec['gid']
        try: yield spec
        finally: self.as_actor = old

    def restore_role(self, name):
        with self.role(name) as manifest: return u.restore(manifest)

    def restore_all(self):
        return {name: self.restore_role(name) for name in self.unit_custody['roles']}

    def issue(self):
        return u.seal_running_copies(self.install, self.release, self.running_intent)

    def test_cold_exact_roles_root_seal_and_idempotent_repeat(self):
        proof = self.run_units()
        self.assertEqual(len(proof['files']), 16)
        self.assertFalse(proof['activationAuthorized']); self.assertFalse(proof['updaterOwned'])
        first = self.restore_all()
        self.assertEqual(set(first['rootful']['files']), {'edge.env'})
        self.assertEqual(set(first['rootless-apps']['files']), {'webapp.env'})
        sealed = self.issue()
        self.assertFalse(sealed['activationAuthorized']); self.assertFalse(sealed['readinessAuthorized'])
        for name, role in self.unit_custody['roles'].items():
            path = Path(role['custodyFile']); mode = 0o400 if role['uid'] == 0 else 0o440
            self.assertEqual((path.stat().st_uid, path.stat().st_gid, stat.S_IMODE(path.stat().st_mode)), (0, role['gid'], mode))
            self.assertNotIn('/runtime/', str(path))
        repeated = self.restore_all()
        self.assertTrue(repeated['rootful']['idempotent']); self.assertTrue(repeated['rootless-apps']['idempotent'])
        self.assertEqual(self.issue()['bootId'], sealed['bootId'])
        self.assertTrue(any(flags & os.O_PATH for path, flags, xdev in self.restore_events if path.is_relative_to(self.scope)))

    def test_prepare_no_write_and_exact_rootful_membership(self):
        before = (self.install / '.install-intent.json').read_bytes()
        custody = self.prepare_units()
        self.assertEqual(before, (self.install / '.install-intent.json').read_bytes())
        self.assertEqual(self.mutations, [])
        self.assertEqual(set(custody['roles']['rootful']['files']), {'edge.env'})
        self.assertEqual(custody['roles']['rootful']['uid'], 0)

    def test_rootful_empty_no_store_read_or_export(self):
        self.run_units(); self.restore_all(); self.issue()
        self.assertEqual(self.unit_custody['roles']['rootful']['files'], {})
        self.assertIsNone(self.unit_custody['roles']['rootful']['store'])
        self.assertFalse((self.install / 'runtime-env').exists())

    def test_no_sameprocess_custody_refuses(self):
        with self.assertRaises(ValueError): u.publish(self.install, self.release, self.prior)

    def test_existing_foreign_unit_refuses_before_write(self):
        target = self.host / 'etc/systemd/system' / u.UNIT
        self.put(target, b'foreign'); target.chmod(0o644)
        with self.assertRaises(ValueError): self.prepare_units()
        self.assertEqual(target.read_bytes(), b'foreign')

    def test_missing_rootful_real_handoff_refuses(self):
        self.prior.pop('rootfulEnvironmentStoreHandoff'); self.write_records(self.prior)
        with self.assertRaises(ValueError): self.prepare_units()

    def test_missing_empty_domain_handoff_refuses(self):
        self.prior['domainRuntimeProjections']['finance'].pop('environmentStoreHandoff'); self.write_records(self.prior)
        with self.assertRaises(ValueError): self.prepare_units()

    def test_selected_file_proof_not_opaque_permission(self):
        self.prior['nativeUnitFiles']['files'][str(self.path)]['sha256'] = '0' * 64; self.write_records(self.prior)
        with self.assertRaises(ValueError): self.prepare_units()

    def test_dual_record_custody_required(self):
        self.prepare_units(); self.units_intent = dict(self.prior, nativeRuntimeEnvUnitCustody=self.unit_custody)
        with self.assertRaises(ValueError): self.publish_units()

    def test_unrelated_names_preserved_and_never_copied(self):
        self.run_units()
        root = self.install / 'runtime-env'; sentinel = root / 'unselected.env'; sentinel.symlink_to('/never-read')
        self.restore_all()
        self.assertTrue(sentinel.is_symlink())
        self.assertFalse((self.host / 'run/webservices/unselected.env').exists())
        sibling = self.host / 'run/webservices/keep'; sibling.symlink_to('/never-read')
        self.issue(); self.restore_all(); self.assertTrue(sibling.is_symlink())

    def test_sameboot_repeat_before_root_seal_refuses(self):
        self.run_units(); self.restore_all()
        with self.assertRaisesRegex(u._runtime['RootCopyCustodyRequired'], 'Root copy custody is not sealed'):
            self.restore_role('rootless-apps')

    def test_wrong_existing_selected_runtime_never_adopted(self):
        self.run_units()
        spec = self.unit_custody['roles']['rootful']; runtime = Path(spec['runtimeStore']); self.mkdir(runtime)
        self.put(runtime / 'edge.env', b'FOREIGN'); self.set_owner(runtime / 'edge.env', 0, 0)
        with self.assertRaises((ValueError, OSError)): self.restore_role('rootful')
        self.assertEqual((runtime / 'edge.env').read_bytes(), b'FOREIGN')

    def test_stale_boot_existing_receipt_refuses_fresh_boot_absent_recopies(self):
        self.run_units(); self.restore_all(); self.issue()
        with patch.dict(u._runtime, _boot=lambda: 'ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee',
                        _mount=lambda fd: 92 if self.fd_paths[fd].is_relative_to(self.host / 'run') else 91):
            with self.assertRaises(ValueError): self.restore_role('rootful')
            # A genuine new runtime anchor/role directory identity, not only a
            # changed boot string. Keep the old synthetic boot tree as evidence.
            (self.host / 'run').rename(self.host / 'inert-old-boot-run')
            self.mkdir(self.host / 'run/user'); (self.host / 'run/user').chmod(0o755); (self.host / 'run').chmod(0o755)
            for row in self.rows:
                anchor = self.host / 'run/user' / str(row['uid']); self.mkdir(anchor)
                self.set_owner(anchor, row['uid'], self.accounts[row['user']].pw_gid)
            self.restore_all(); proof = self.issue(); self.restore_all()
            self.assertEqual(proof['copies']['rootful']['copy']['runtimeAnchor']['mountId'], 92)

    def test_actor_authored_receipt_refuses(self):
        self.run_units(); self.restore_all(); self.issue()
        role = self.unit_custody['roles']['rootless-apps']; path = Path(role['custodyFile'])
        self.set_owner(path, role['uid'], role['gid'])
        with self.assertRaises(ValueError): self.restore_role('rootless-apps')
        with self.assertRaises(ValueError): self.issue()

    def test_root_issuer_wrong_runtime_hash_refuses(self):
        self.run_units(); self.restore_all()
        path = self.host / 'run/webservices/edge.env'; path.write_bytes(b'FOREIGN')
        with self.assertRaises(ValueError): self.issue()
        self.assertFalse((self.release / 'runtime-env-copy-custody.json').exists())

    def test_no_real_tmpfs_no_restore(self):
        self.run_units()
        with patch.dict(u._runtime, _tmpfs=lambda fd: False):
            with self.assertRaises(ValueError): self.restore_role('rootful')
        self.assertFalse((self.host / 'run/webservices').exists())

    def test_source_hash_drift_refuses_before_copy(self):
        self.run_units(); target = self.install / 'runtime-env/edge.env'; target.write_bytes(b'FOREIGN')
        with self.assertRaises(ValueError): self.restore_role('rootful')
        self.assertFalse((self.host / 'run/webservices').exists())

    def test_original_runtime_inode_not_only_hash(self):
        self.run_units(); self.restore_all(); self.issue()
        target = self.host / 'run/webservices/edge.env'; body = target.read_bytes(); target.rename(target.with_name('retained'))
        self.put(target, body)
        with self.assertRaises(ValueError): self.restore_role('rootful')

    def test_root_receipt_hardlink_symlink_acl_refuse(self):
        self.run_units(); self.restore_all(); self.issue()
        role = self.unit_custody['roles']['rootful']; path = Path(role['custodyFile'])
        os.link(path, self.base / 'receipt-alias')
        with self.assertRaises(ValueError): self.restore_role('rootful')
        (self.base / 'receipt-alias').unlink()
        self.acls[self.key(path)] = (b'foreign', b'')
        with self.assertRaises(ValueError): self.restore_role('rootful')

    def test_unknown_root_owned_receipt_not_overwritten(self):
        self.run_units(); self.restore_all()
        path = self.release / 'runtime-env-copy-custody.json'; self.put(path, b'{}\n'); path.chmod(0o400)
        with self.assertRaises(ValueError): self.issue()
        self.assertEqual(path.read_bytes(), b'{}\n')

    def test_actual_unit_byte_drift_prevents_root_seal(self):
        self.run_units(); self.restore_all()
        path = self.host / 'etc/systemd/system' / u.UNIT; path.write_bytes(b'foreign')
        with self.assertRaises(ValueError): self.issue()

    def test_mixed_present_absent_runtime_refuses_without_partial_copy(self):
        self.run_units(); spec = self.unit_custody['roles']['rootful']; runtime = Path(spec['runtimeStore'])
        self.mkdir(runtime); self.put(runtime / 'edge.env', (self.install / 'runtime-env/edge.env').read_bytes())
        before = p.identity((runtime / 'edge.env').stat())
        with self.assertRaises(ValueError): self.restore_role('rootful')
        self.assertEqual(before, p.identity((runtime / 'edge.env').stat()))
        self.assertFalse((runtime / 'edge-second.env').exists())

    def test_legacy_adjunct_exact_old_source_replace_preserves_parent_and_other_names(self):
        source = str(self.install / 'runtime-env'); runtime = str(self.host / 'run/webservices')
        folder = self.host / 'etc/systemd/system'; path = folder / u.UNIT
        self.put(path, u.legacy_unit(source, runtime)); path.chmod(0o644)
        drop = folder / 'webservices.target.d'; self.mkdir(drop); drop.chmod(0o755)
        self.put(drop / u.DROPIN, u.render_dropin()); (drop / u.DROPIN).chmod(0o644)
        sentinel = drop / 'keep.note'; sentinel.symlink_to('/never-read')
        before = p.identity(drop.stat())[:6]
        proof = self.run_units()
        self.assertEqual(before, p.identity(drop.stat())[:6]); self.assertTrue(sentinel.is_symlink())
        self.assertEqual(path.read_bytes(), u.render_unit(self.unit_custody['roles']['rootful']))
        self.assertEqual(len(proof['files']), 16)

    def test_unknown_helper_override_and_foreign_target_conf_preserved(self):
        folder = self.host / 'etc/systemd/system'
        self.mkdir(folder / (u.UNIT + '.d'))
        with self.assertRaises(ValueError): self.prepare_units()
        (folder / (u.UNIT + '.d')).rmdir()
        drop = folder / 'webservices.target.d'; self.mkdir(drop)
        foreign = drop / 'foreign.conf'; self.put(foreign, b'FOREIGN')
        with self.assertRaises(ValueError): self.prepare_units()
        self.assertEqual(foreign.read_bytes(), b'FOREIGN')

    def test_source_uid_gid_mode_acl_and_hardlink_no_export(self):
        self.run_units(); source = self.install / 'runtime-env/edge.env'
        for mode in (0o644, 0o660):
            source.chmod(mode)
            with self.assertRaises(ValueError): self.restore_role('rootful')
        source.chmod(0o600); self.acls[self.key(source)] = (b'foreign', b'')
        with self.assertRaises(ValueError): self.restore_role('rootful')
        self.acls.pop(self.key(source)); os.link(source, self.base / 'source-alias')
        with self.assertRaises(ValueError): self.restore_role('rootful')
        self.assertFalse((self.host / 'run/webservices').exists())

    def test_runtime_anchor_bad_owner_mode_acl_or_fs_refuses(self):
        self.run_units(); role = self.unit_custody['roles']['rootless-apps']
        anchor = self.host / 'run/user' / str(role['uid'])
        anchor.chmod(0o755)
        with self.assertRaises(ValueError): self.restore_role('rootless-apps')
        anchor.chmod(0o700); self.set_owner(anchor, 0, 0)
        with self.assertRaises(ValueError): self.restore_role('rootless-apps')
        self.set_owner(anchor, role['uid'], role['gid']); self.acls[self.key(anchor)] = (b'foreign', b'')
        with self.assertRaises(ValueError): self.restore_role('rootless-apps')

    def test_root_receipt_symlink_and_stale_original_inode_refuse(self):
        self.run_units(); self.restore_all(); self.issue()
        role = self.unit_custody['roles']['rootless-apps']; path = Path(role['custodyFile'])
        original = path.with_name('retained-root-receipt'); path.rename(original); path.symlink_to(original)
        with self.assertRaises(OSError): self.restore_role('rootless-apps')
        path.unlink(); original.rename(path)
        target = Path(role['runtimeStore']) / 'webapp.env'; body = target.read_bytes(); target.rename(target.with_name('retained'))
        self.put(target, body); self.set_owner(target, role['uid'], role['gid'])
        with self.assertRaises(ValueError): self.restore_role('rootless-apps')

    def test_active_root_sealer_uses_real_running_verifier_not_offline_bypass(self):
        self.run_units(); self.restore_all()
        for row in self.rows:
            state = Path(row['stateRoot']); (state / 'current').symlink_to(state / 'releases' / self.release.name)
        (self.install / 'current').symlink_to(self.release)
        self.running_intent['phase'] = 'active'; self.write_records(self.running_intent)
        original = u.v.Snapshot.absolute
        def absolute(snapshot, path, operator=None):
            actual = self.host / 'run/user' if path == Path('/run/user') else path
            return original(snapshot, actual, operator)
        with patch.object(u.v.Snapshot, 'absolute', new=absolute):
            proof = self.issue()
        self.assertEqual(set(proof['copies']), set(self.unit_custody['roles']))
        self.assertFalse(proof['readinessAuthorized'])

    def test_invalid_root_issuer_phase_refuses(self):
        self.run_units(); self.restore_all(); self.running_intent['phase'] = 'failed'; self.write_records(self.running_intent)
        with self.assertRaises(ValueError): self.issue()

    def test_root_receipt_shape_not_opaque_matching_json(self):
        self.run_units(); self.restore_all(); self.issue()
        role = self.unit_custody['roles']['rootful']; path = Path(role['custodyFile'])
        value = p.strict(path.read_bytes()); value.pop('runtimeAnchor'); path.chmod(0o600)
        self.put(path, p.encoded(value)); path.chmod(0o400)
        with self.assertRaises(ValueError): self.restore_role('rootful')
        with self.assertRaises(ValueError): self.issue()

    def test_actual_helper_root_gate_never_ignored(self):
        self.prepare_units(); self.seal_units()
        def active(command, **kwargs):
            return SimpleNamespace(returncode=0, stdout='Id=' + command[2] + '\nActiveState=active\nMainPID=77\nJob=\n')
        with patch.object(subprocess, 'run', new=active):
            with self.assertRaises(ValueError): self.publish_units()
        self.assertFalse((self.host / 'etc/systemd/system' / u.UNIT).exists())

    def test_runtime_no_replace_race_preserves_unknown_existing_name(self):
        self.run_units(); original = u._runtime['rename']; path = self.host / 'run/webservices/edge.env'
        def rename(parent, source, name):
            if name == 'edge.env': self.put(path, b'FOREIGN')
            return original(parent, source, name)
        with patch.dict(u._runtime, rename=rename):
            with self.assertRaises(OSError): self.restore_role('rootful')
        self.assertEqual(path.read_bytes(), b'FOREIGN')

    def test_source_issued_receipt_foreign_candidate_never_adopted(self):
        self.run_units(); self.restore_all(); self.issue()
        path = self.release / 'runtime-env-copy-custody.json'; value = p.strict(path.read_bytes())
        value['release'] = str(self.install / 'releases/foreign'); path.chmod(0o600)
        self.put(path, p.encoded(value)); path.chmod(0o400)
        before = path.read_bytes()
        with self.assertRaises(ValueError): self.restore_role('rootful')
        with self.assertRaises(ValueError): self.issue()
        self.assertEqual(path.read_bytes(), before)

    def test_unit_stage_race_restores_foreign_name_without_reading(self):
        self.prepare_units(); self.seal_units(); original = f.m.rename; foreign = []
        folder = self.host / 'etc/systemd/system'
        def race(parent, source, target, exchange=False):
            if not foreign and self.fd_paths[parent] == folder and target == u.UNIT:
                held = folder / source; held.rename(folder / (source + '-held-original'))
                self.put(held, b'FOREIGN'); held.chmod(0o644); foreign.append(held)
            return original(parent, source, target, exchange)
        with patch.object(f.m, 'rename', new=race):
            with self.assertRaises(ValueError): self.publish_units()
        self.assertFalse((folder / u.UNIT).exists()); self.assertEqual(foreign[0].read_bytes(), b'FOREIGN')
        self.assertIn('nativeRuntimeEnvUnitCustody', p.strict((self.install / '.install-intent.json').read_bytes()))

    def test_root_receipt_stage_race_preserves_previous_root_receipt(self):
        self.run_units(); self.restore_all(); self.issue()
        path = self.release / 'runtime-env-copy-custody.json'; before = path.read_bytes(); before_id = p.identity(path.stat())
        original = f.m.rename; foreign = []
        def race(parent, source, target, exchange=False):
            if not foreign and target == path.name and self.fd_paths[parent] == self.release:
                held = self.release / source; held.rename(self.release / (source + '-held-original'))
                self.put(held, b'FOREIGN'); held.chmod(0o400); foreign.append(held)
            return original(parent, source, target, exchange)
        with patch.object(f.m, 'rename', new=race):
            with self.assertRaises(ValueError): self.issue()
        self.assertEqual(path.read_bytes(), before); self.assertEqual(p.identity(path.stat())[:-1], before_id[:-1])
        self.assertEqual(foreign[0].read_bytes(), b'FOREIGN')

    def test_verbatim_entry_reports_specific_unsealed_dependency_without_values(self):
        import base64
        import io
        import sys
        self.run_units(); self.restore_all()
        prefix, entry = u.RUNTIME_PROGRAM.rsplit("\nif __name__=='__main__':", 1)
        namespace = {'__name__': '__main__'}; exec(compile(prefix, '<exact-prefix>', 'exec'), namespace)
        for key in ('HOST', 'child', '_uid', '_gid', '_mount', '_tmpfs', '_acl', '_boot'):
            namespace[key] = u._runtime[key]
        output = io.StringIO(); argv = ['-c', base64.b64encode(p.encoded(self.unit_custody['roles']['rootful'])).decode()]
        with patch.object(sys, 'argv', new=argv), contextlib.redirect_stderr(output):
            with self.assertRaises(SystemExit) as caught:
                exec(compile("if __name__=='__main__':" + entry, '<exact-entry>', 'exec'), namespace)
        self.assertEqual(caught.exception.code, 1)
        self.assertEqual(output.getvalue(), 'current-boot Root copy custody is not sealed; canonical Root sealing/disposition required\n')
        self.assertNotIn('synthetic.invalid', output.getvalue())

    def select_active(self):
        for row in self.rows:
            state = Path(row['stateRoot']); (state / 'current').symlink_to(state / 'releases' / self.release.name)
        (self.install / 'current').symlink_to(self.release)
        self.running_intent['phase'] = 'active'; self.write_records(self.running_intent)

    def test_prestart_source_units_only_when_runtime_completely_absent(self):
        self.run_units(); (self.host / 'run').rename(self.host / 'inert-no-runtime')
        before = (self.install / '.install-intent.json').read_bytes(); self.restore_events.clear(); self.mutations.clear()
        proof = u.verify_prepared_units(self.install, self.release, self.running_intent)
        self.assertFalse(proof['runningEnvironmentChecked']); self.assertFalse(proof['activationAuthorized'])
        self.assertFalse((self.host / 'run').exists()); self.assertEqual(self.mutations, [])
        self.assertEqual(before, (self.install / '.install-intent.json').read_bytes())
        self.assertFalse(any(path.is_relative_to(self.host / 'run') for path, flags, xdev in self.restore_events))
        with self.assertRaises((ValueError, OSError)): self.issue()

    def test_active_prestart_surviving_root_cues_without_runtime_no_phase_rebase(self):
        self.run_units(); self.restore_all(); self.issue(); self.select_active()
        (self.host / 'run').rename(self.host / 'inert-no-runtime')
        before = (self.install / '.install-intent.json').read_bytes(); self.restore_events.clear(); self.mutations.clear()
        proof = u.verify_prepared_units(self.install, self.release, self.running_intent)
        self.assertFalse(proof['runningEnvironmentChecked']); self.assertFalse(proof['readinessAuthorized'])
        self.assertEqual(before, (self.install / '.install-intent.json').read_bytes()); self.assertEqual(self.mutations, [])
        self.assertFalse(any(path.is_relative_to(self.host / 'run') for path, flags, xdev in self.restore_events))

    def test_prestart_unknown_actor_cue_refuses_before_any_runtime(self):
        self.run_units(); self.restore_all(); self.issue()
        role = self.unit_custody['roles']['rootless-apps']; self.set_owner(Path(role['custodyFile']), role['uid'], role['gid'])
        (self.host / 'run').rename(self.host / 'inert-no-runtime')
        with self.assertRaises(ValueError): u.verify_prepared_units(self.install, self.release, self.running_intent)
        self.assertFalse((self.host / 'run').exists())

    def test_prestart_actual_persistent_source_drift_never_ignored(self):
        self.run_units(); (self.host / 'run').rename(self.host / 'inert-no-runtime')
        (self.install / 'runtime-env/edge.env').write_bytes(b'FOREIGN')
        with self.assertRaises(ValueError): u.verify_prepared_units(self.install, self.release, self.running_intent)

    def test_nonroot_cannot_prepare_prestart_or_issue_root_copy_custody(self):
        self.run_units(); self.restore_all()
        with patch.object(os, 'geteuid', new=lambda: 1000):
            with self.assertRaises(ValueError): u.verify_prepared_units(self.install, self.release, self.running_intent)
            with self.assertRaises(ValueError): self.issue()
            with self.assertRaises(ValueError): u.prepare_custody(self.install, self.release, self.prior)
        self.assertFalse((self.release / 'runtime-env-copy-custody.json').exists())

    def test_restore_wrong_role_uid_cannot_read_or_copy_source(self):
        self.run_units()
        with patch.dict(u._runtime, _uid=lambda: 782):
            with self.assertRaises(ValueError): self.restore_role('rootless-apps')
        role = self.unit_custody['roles']['rootless-apps']; self.assertFalse(Path(role['runtimeStore']).exists())

    def test_opath_acl_exact_temp_fd_fallback(self):
        import errno
        prefix = u.RUNTIME_PROGRAM.rsplit("\nif __name__=='__main__':", 1)[0]
        namespace = {'__name__': '_actual_acl_temp_fd'}; exec(compile(prefix, '<exact-prefix>', 'exec'), namespace)
        path = self.base / 'execute-only-real-fd'; self.mkdir(path); path.chmod(0o111)
        fd = os.open(path, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for key in ('system.posix_acl_access', 'system.posix_acl_default'):
                try: expected = os.getxattr('/proc/self/fd/' + str(fd), key)
                except OSError as error:
                    if error.errno != errno.ENODATA: raise
                    expected = b''
                self.assertEqual(namespace['_acl'](fd, key), expected)
        finally: os.close(fd); path.chmod(0o700)

    def test_prestart_source_and_cue_bindings_transition_only_after_real_root_seal(self):
        self.run_units()
        before = u.verify_prepared_units(self.install, self.release, self.running_intent)
        self.assertEqual(before['copyCustodySha256'], p.sha(p.encoded({role: None for role in self.unit_custody['roles']})))
        self.restore_all(); issued = self.issue()
        after = u.verify_prepared_units(self.install, self.release, self.running_intent)
        cue_map = {role: proof['receipt'] for role, proof in issued['copies'].items()}
        self.assertEqual(after['copyCustodySha256'], p.sha(p.encoded(cue_map)))
        self.assertEqual(before['sourceSha256'], after['sourceSha256'])
        self.assertEqual(before['intentSha256'], after['intentSha256'])
        self.assertNotEqual(before['bindingSha256'], after['bindingSha256'])
        self.assertNotEqual(before['copyCustodySha256'], after['copyCustodySha256'])
        self.assertEqual(before['copyCustodySha256'], p.sha(p.encoded(dict.fromkeys(cue_map))))

    def test_runtime_program_execstart_manifest_contains_no_plaintext_env(self):
        self.prepare_units()
        body = u.render_unit(self.unit_custody['roles']['rootful'])
        self.assertIn(b'/usr/bin/python3 -I -B -c ', body)
        self.assertNotIn(b'synthetic.invalid', body); self.assertNotIn(b'*.env', body)
        self.assertNotIn(b'root-master-sentinel', body); self.assertNotIn(b'.install-intent.json', body)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--group', type=int, choices=range(1, 17))
    group.add_argument('--match')
    args = parser.parse_args()
    names = [name for name in Units.__dict__ if name.startswith('test_')]
    if args.group is not None: names = [name for index, name in enumerate(names) if index % 16 == args.group - 1]
    if args.match: names = [name for name in names if args.match in name]
    if not names: parser.error('no matching tests')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Units(name) for name in names))
    raise SystemExit(not result.wasSuccessful())
