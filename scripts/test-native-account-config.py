#!/usr/bin/env python3
"""Isolated native account config: real temp FD/openat2/anonymous atomic link.

Model UID/GID/NSS/ACL/offline observations only; subprocess forbidden. The
metadata fixture is reused ONLY as a sealed-source/temp-FD9 builder, never by
running its settled tests or sealing operation. No rootful-store dependency.
"""
import errno
import importlib.util
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).absolute().parents[1]
RAW_MKDIR, RAW_FCHMOD, RAW_LINK = os.mkdir, os.fchmod, os.link


def load(name, source):
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    exec(compile(source.read_bytes(), str(source), 'exec'), module.__dict__)
    return module


fixture = load('account_config_fixture', ROOT / 'scripts/test-native-metadata-owner.py')
m = load('tested_account_config', ROOT / 'runtime-generator/podman-ops/prepare-native-account-config.py')
p, o = m.p, m.o


class AccountConfig(unittest.TestCase):
    key = fixture.Metadata.key
    put = fixture.Metadata.put
    mutate_json = fixture.Metadata.mutate_json
    reseal_profile = fixture.Metadata.reseal_profile
    populate = fixture.Metadata.populate
    write_records = fixture.Metadata.write_records
    close_lock = fixture.Metadata.close_lock
    set_owner = fixture.Metadata.set_owner
    set_native_marker_acl = fixture.Metadata.set_native_marker_acl

    def setUp(self):
        fixture.Metadata.setUp(self)
        self.domain = 'test-runners'
        self.row = next(row for row in self.rows if row['name'] == self.domain)
        self.home_parent = self.base / 'home'; RAW_MKDIR(self.home_parent, 0o700)
        self.home = self.home_parent / self.row['user']; RAW_MKDIR(self.home, 0o700)
        self.accounts = {'operator': self.operator}
        self.accounts.update({user: SimpleNamespace(pw_uid=uid, pw_gid=uid + 3000, pw_name=user, pw_dir='/home/' + user)
                              for uid, user in m.native.IDENTITIES.values()})
        self.groups = {name: SimpleNamespace(gr_gid=account.pw_gid, gr_name=name, gr_mem=[])
                       for name, account in self.accounts.items()}
        self.actor = self.accounts[self.row['user']]
        self.set_owner(self.home, self.actor.pw_uid, self.actor.pw_gid)
        self.root.chmod(0o700)
        self.release = self.root / 'releases/fresh'; RAW_MKDIR(self.release, 0o700)
        self.intent = dict(schemaVersion=1, phase='preparing', release=str(self.release), previousRelease=None,
                           steps=['preparing'], inputs=m.journal.fingerprint(self.bundle))
        self.write_intents()
        self.created_dirs, self.changed_nodes, self.published = set(), [], []
        self.original = set(self.base.rglob('*'))
        self.raw_write = os.write
        self.offline = SimpleNamespace(calls=0, hook=None)
        def fdpath(fd):
            path = Path(os.readlink('/proc/self/fd/' + str(fd)))
            self.assertTrue(str(path).startswith(str(self.base) + '/')); return path
        self.fdpath = fdpath
        def mkdir(name, mode=0o777, *, dir_fd=None):
            path = Path(name) if dir_fd is None else fdpath(dir_fd) / name
            self.assertIn(path, {self.home / relative for relative in m.CONFIG_DIRS})
            self.assertNotIn(path, self.original)
            RAW_MKDIR(name, mode, dir_fd=dir_fd)
            self.created_dirs.add(path)
            parent = self.key(path.parent)
            self.virtual[self.key(path)] = (0, self.virtual.get(parent, (0, 0))[1])
            access, default = self.acls.get(parent, (b'', b''))
            if default: self.acls[self.key(path)] = default, default
        def chown(fd, uid, gid):
            info = self.raw_fstat(fd); key = info.st_dev, info.st_ino
            self.assertEqual((uid, gid), (self.actor.pw_uid, self.actor.pw_gid))
            if stat.S_ISDIR(info.st_mode):
                self.assertIn(fdpath(fd), self.created_dirs); self.assertEqual(os.listdir(fd), [])
            else:
                self.assertTrue(stat.S_ISREG(info.st_mode)); self.assertEqual(info.st_nlink, 0)
            self.virtual[key] = uid, gid
            self.changed_nodes.append(('chown', key))
        def chmod(fd, mode):
            info = self.raw_fstat(fd)
            if stat.S_ISDIR(info.st_mode):
                self.assertIn(fdpath(fd), self.created_dirs); self.assertEqual(mode, 0o700)
            else:
                self.assertTrue(stat.S_ISREG(info.st_mode)); self.assertEqual(info.st_nlink, 0); self.assertEqual(mode, 0o600)
            RAW_FCHMOD(fd, mode); self.changed_nodes.append(('chmod', (info.st_dev, info.st_ino)))
        def remove(fd, attribute):
            path = fdpath(fd)
            self.assertIn(path, self.created_dirs); self.assertEqual(os.listdir(fd), [])
            access, default = self.acls.get(self.key(path), (b'', b''))
            value = access if attribute == 'system.posix_acl_access' else default
            if not value: raise OSError(errno.ENODATA, 'fixture no ACL')
            self.acls[self.key(path)] = (b'', default) if attribute == 'system.posix_acl_access' else (access, b'')
        def acl(fd, name):
            info = self.raw_fstat(fd)
            value = self.acls.get((info.st_dev, info.st_ino), (b'', b''))
            return value[0 if name == 'system.posix_acl_access' else 1]
        def offline(bundle, domain):
            self.assertEqual((bundle, domain), (self.bundle, self.domain)); self.offline.calls += 1
            if self.offline.hook: self.offline.hook()
            return dict(domain=domain, uid=self.actor.pw_uid, status='offline-preparation-only')
        def publish(source, name, **kwargs):
            self.assertTrue(source.startswith('/proc/self/fd/'))
            fd = int(source.rsplit('/', 1)[1]); info = self.raw_fstat(fd)
            self.assertEqual(info.st_nlink, 0); self.assertGreater(info.st_size, 0)
            self.assertEqual(kwargs.get('follow_symlinks'), True)
            self.assertEqual(fdpath(kwargs['dst_dir_fd']), self.home / '.config/containers')
            self.assertIn(name, m.configurations(self.row))
            RAW_LINK(source, name, **kwargs); self.published.append(name)
        # Model only ABOVE-fixture ancestor times as stable protected /var/lib
        # ancestry; unrelated agents may mutate /tmp concurrently. All actual
        # fixture inode metadata, path replacement, links and mounts stay real.
        above = {self.key(path): self.raw_lstat(path) for path in self.base.parents}
        stat_model, lstat_model, fstat_model = os.stat, os.lstat, os.fstat
        class StableAncestor:
            def __init__(inner, value):
                inner.value = value
                old = above.get((value.st_dev, value.st_ino))
                if old is not None:
                    for field in ('st_nlink', 'st_size', 'st_mtime', 'st_ctime', 'st_mtime_ns', 'st_ctime_ns'):
                        setattr(inner, field, getattr(old, field))
            def __getattr__(inner, field): return getattr(inner.value, field)
        items = [patch.object(m, 'HOME_PARENT', self.home_parent),
            patch.object(os, 'stat', side_effect=lambda *a, **kw: StableAncestor(stat_model(*a, **kw))),
            patch.object(os, 'lstat', side_effect=lambda *a, **kw: StableAncestor(lstat_model(*a, **kw))),
            patch.object(os, 'fstat', side_effect=lambda *a, **kw: StableAncestor(fstat_model(*a, **kw))),
            patch.object(os, 'mkdir', side_effect=mkdir), patch.object(os, 'fchown', side_effect=chown),
            patch.object(os, 'fchmod', side_effect=chmod), patch.object(os, 'removexattr', side_effect=remove),
            patch.object(os, 'link', side_effect=publish), patch.object(p, 'acl_bytes', side_effect=acl),
            patch.object(o, 'EXTERNAL_OPERATOR', self.external),
            patch.object(o.pwd, 'getpwnam', side_effect=lambda name: self.accounts[name]),
            patch.object(o.pwd, 'getpwuid', side_effect=lambda uid: next(account for account in self.accounts.values() if account.pw_uid == uid)),
            patch.object(o.pwd, 'getpwall', side_effect=lambda: list(self.accounts.values())),
            patch.object(o.grp, 'getgrnam', side_effect=lambda name: self.groups[name]),
            patch.object(o.grp, 'getgrgid', side_effect=lambda gid: next(group for group in self.groups.values() if group.gr_gid == gid)),
            patch.object(m.storage, 'namespace_root_id', side_effect=lambda user: next(row['subuidStart'] for row in self.rows if row['user'] == user)),
            patch.object(m.journal, 'assert_domain_offline', side_effect=offline)]
        for item in items: item.start()

    def write_intents(self):
        self.put(self.root / '.install-intent.json', p.encoded(self.intent))
        self.put(self.release / 'installation-receipt.json', p.encoded(self.intent))

    def prepare(self): return m.prepare(self.root, self.bundle, self.domain)

    def owner(self):
        owner = m.Preparation(self.root, self.bundle, self.domain)
        self.addCleanup(owner.close); return owner

    def existing_dirs(self, mode=0o755):
        for relative in m.CONFIG_DIRS:
            path = self.home / relative
            if not path.exists(): RAW_MKDIR(path, mode)
            path.chmod(mode); self.set_owner(path, self.actor.pw_uid, self.actor.pw_gid)
        self.original.update(self.home.rglob('*'))

    def existing_files(self):
        self.existing_dirs()
        for name, body in m.configurations(self.row).items():
            path = self.home / '.config/containers' / name
            self.put(path, body); self.set_owner(path, self.actor.pw_uid, self.actor.pw_gid)
            self.original.add(path)

    def test_fresh_exact5dirs_2atomicfiles_and_reuse(self):
        before_scope = dict(self.acls)
        intent = (self.root / '.install-intent.json').read_bytes()
        proof = self.prepare()
        self.assertEqual(self.created_dirs, {self.home / path for path in m.CONFIG_DIRS})
        self.assertEqual(set(self.published), {'storage.conf', 'containers.conf'})
        self.assertEqual(len(proof['directories']), 6); self.assertEqual(len(proof['files']), 2)
        for path, value in proof['directories'].items():
            self.assertEqual((value['uid'], value['gid'], value['mode'], value['acl'], value['defaultAcl']),
                             (self.actor.pw_uid, self.actor.pw_gid, 0o700, '', ''))
        for name, body in m.configurations(self.row).items():
            path = self.home / '.config/containers' / name
            self.assertEqual(path.read_bytes(), body)
            self.assertEqual(proof['files'][str(path)]['sha256'], p.sha(body))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        changed, published = list(self.changed_nodes), list(self.published)
        again = self.prepare()
        self.assertFalse(any(value['created'] for value in again['directories'].values()))
        self.assertFalse(any(value['created'] for value in again['files'].values()))
        self.assertEqual(self.changed_nodes, changed); self.assertEqual(self.published, published)
        for key, value in before_scope.items(): self.assertEqual(self.acls[key], value)
        self.assertEqual((self.root / '.install-intent.json').read_bytes(), intent)
        self.assertEqual(list(self.release.iterdir()), [self.release / 'installation-receipt.json'])
        self.assertFalse(proof['activationAuthorized'])
        self.assertGreater(self.offline.calls, 2)

    def test_existing755_dirs_metadata_and_unknown_names_unread(self):
        self.existing_dirs()
        unknown = self.home / '.config/containers/systemd/unselected-do-not-read'
        os.mkfifo(unknown)
        (self.home / '.ssh').symlink_to('/does-not-exist/private-auth')
        before = {path: self.raw_lstat(path) for path in [self.home, *[self.home / name for name in m.CONFIG_DIRS]]}
        real_listdir = os.listdir
        def no_home_lists(fd):
            if isinstance(fd, int):
                path = Path(os.readlink('/proc/self/fd/' + str(fd)))
                self.assertFalse(path == self.home or path.is_relative_to(self.home))
            return real_listdir(fd)
        with patch.object(os, 'listdir', side_effect=no_home_lists): proof = self.prepare()
        self.assertEqual(self.created_dirs, set())
        self.assertFalse(any(value['created'] for value in proof['directories'].values()))
        for path, old in before.items():
            current = self.raw_lstat(path)
            self.assertEqual((current.st_dev, current.st_ino, current.st_uid, current.st_gid, current.st_mode),
                             (old.st_dev, old.st_ino, old.st_uid, old.st_gid, old.st_mode))
        self.assertTrue(stat.S_ISFIFO(self.raw_lstat(unknown).st_mode))

    def test_existing700_and750_dirs_supported_not_chmodded(self):
        self.existing_dirs(0o750)
        (self.home / '.config/systemd').chmod(0o700)
        proof = self.prepare()
        self.assertEqual(proof['directories'][str(self.home / '.config/containers')]['mode'], 0o750)
        self.assertEqual(proof['directories'][str(self.home / '.config/systemd')]['mode'], 0o700)
        self.assertFalse(any(kind == 'chmod' and key == self.key(self.home / '.config') for kind, key in self.changed_nodes))

    def test_existing_identical_files_leave_inode_mode_ownership_unchanged(self):
        self.existing_files()
        paths = [self.home / '.config/containers' / name for name in m.configurations(self.row)]
        before = {path: p.identity(path.stat()) for path in paths}
        self.prepare()
        self.assertEqual({path: p.identity(path.stat()) for path in paths}, before)
        self.assertEqual(self.changed_nodes, []); self.assertEqual(self.published, [])

    def test_missing_home_is_not_created_or_adopted(self):
        self.home.rmdir()
        with self.assertRaises((ValueError, OSError)): self.prepare()
        self.assertFalse(self.home.exists()); self.assertEqual(self.created_dirs, set())

    def test_home0755_refuses(self):
        self.home.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'directory unsafe'): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_home_foreign_owner_refuses(self):
        self.set_owner(self.home, 1000, 1000)
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_existing_directory_wrong_gid_not_chowned(self):
        self.existing_dirs(); self.set_owner(self.home / '.config', self.actor.pw_uid, 999)
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.changed_nodes, [])

    def test_existing_directory_groupwrite_refuses(self):
        self.existing_dirs(); (self.home / '.config/systemd/user').chmod(0o770)
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_existing_directory_sgid_default_acl_not_repaired(self):
        self.existing_dirs(); path = self.home / '.config/containers'
        path.chmod(0o2755); self.acls[self.key(path)] = fixture.acl(), fixture.acl()
        before = self.acls[self.key(path)]
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.acls[self.key(path)], before); self.assertEqual(self.changed_nodes, [])

    def test_existing_directory_named_acl_refuses(self):
        self.existing_dirs(); path = self.home / '.config'
        self.acls[self.key(path)] = fixture.acl(), b''
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.changed_nodes, [])

    def test_existing_directory_symlink_refuses(self):
        (self.home / '.config').symlink_to(self.base)
        with self.assertRaises((ValueError, OSError)): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_bad_existing_file_preflight_before_any_missing_dir_creation(self):
        self.existing_dirs(); (self.home / '.config/systemd/user').rmdir()
        path = self.home / '.config/containers/storage.conf'; self.put(path, b'authored-do-not-overwrite')
        self.set_owner(path, self.actor.pw_uid, self.actor.pw_gid)
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(path.read_bytes(), b'authored-do-not-overwrite'); self.assertEqual(self.created_dirs, set())

    def test_existing_file_equal_length_wrong_bytes_refuses(self):
        self.existing_files(); path = self.home / '.config/containers/storage.conf'
        data = path.read_bytes(); self.put(path, b'x' + data[1:])
        with self.assertRaisesRegex(ValueError, 'source bytes'): self.prepare()
        self.assertEqual(self.changed_nodes, [])

    def test_existing_file_root_owned_refuses(self):
        self.existing_files(); path = self.home / '.config/containers/storage.conf'; self.set_owner(path, 0, 0)
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.changed_nodes, [])

    def test_existing_file_mode0644_refuses(self):
        self.existing_files(); (self.home / '.config/containers/containers.conf').chmod(0o644)
        with self.assertRaises(ValueError): self.prepare()

    def test_existing_file_hardlink_refuses(self):
        self.existing_files(); path = self.home / '.config/containers/storage.conf'
        RAW_LINK(path, self.home / 'authored-alias')
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.changed_nodes, [])

    def test_existing_file_symlink_refuses(self):
        self.existing_dirs(); (self.home / '.config/containers/storage.conf').symlink_to(self.base / 'foreign')
        with self.assertRaises((ValueError, OSError)): self.prepare()

    def test_existing_file_acl_refuses(self):
        self.existing_files(); self.acls[self.key(self.home / '.config/containers/storage.conf')] = fixture.acl(), b''
        with self.assertRaises(ValueError): self.prepare()

    def test_existing_file_fifo_refuses_without_block(self):
        self.existing_dirs(); os.mkfifo(self.home / '.config/containers/storage.conf')
        with self.assertRaises(ValueError): self.prepare()

    def test_atomic_publication_never_replaces_racing_authored_target(self):
        def race(source, name, **kwargs):
            target = self.fdpath(kwargs['dst_dir_fd']) / name
            self.put(target, b'concurrent-authored')
            RAW_LINK(source, name, **kwargs)
        with patch.object(os, 'link', side_effect=race):
            with self.assertRaises(FileExistsError): self.prepare()
        self.assertEqual((self.home / '.config/containers/storage.conf').read_bytes(), b'concurrent-authored')

    def test_partial_write_never_publishes_visible_file_or_stage(self):
        writes = []
        def fail(fd, data):
            if not writes:
                writes.append(fd); return self.raw_write(fd, data[:5])
            raise OSError(errno.EIO, 'isolated injected write failure')
        with patch.object(os, 'write', side_effect=fail):
            with self.assertRaises(OSError): self.prepare()
        self.assertEqual(list((self.home / '.config/containers').iterdir()), [self.home / '.config/containers/systemd'])
        self.assertEqual(self.published, [])

    def test_native_private_marker_gid_and_raw_acl_preserved_during_account_preparation(self):
        marker,value=self.set_native_marker_acl();body=marker.read_bytes()
        result=self.prepare()
        self.assertFalse(result['activationAuthorized'])
        self.assertEqual(marker.read_bytes(),body)
        self.assertEqual(self.acls[self.key(marker)],(value,b''))
        self.assertEqual(self.virtual[self.key(marker)],(0,1000))
        self.assertNotIn(marker,self.changed_nodes)

    def test_native_marker_foreign_gid_named_actor_mask_and_default_refuse(self):
        marker,value=self.set_native_marker_acl()
        for options in ('gid','named','mask','default'):
            self.set_native_marker_acl()
            if options=='gid':self.set_owner(marker,0,1001)
            elif options=='named':self.set_native_marker_acl(user=1001)
            elif options=='mask':self.set_native_marker_acl(mask=1)
            else:self.acls[self.key(marker)]=(value,value)
            with self.subTest(profile=options),self.assertRaises(ValueError):self.prepare()
            self.assertEqual(self.created_dirs,set())
            self.assertEqual(self.published,[])

    def test_native_marker_profile_does_not_relax_install_intent_group(self):
        self.set_native_marker_acl();self.set_owner(self.root/'.install-intent.json',0,1000)
        with self.assertRaisesRegex(ValueError,'custody differs'):self.prepare()
        self.assertEqual(self.created_dirs,set())

    def test_native_marker_raw_acl_cas_cannot_rebase_to_empty_profile(self):
        marker,value=self.set_native_marker_acl()
        self.offline.hook=lambda:self.acls.__setitem__(self.key(marker),(b'',b''))
        with self.assertRaisesRegex(ValueError,'marker CAS'):self.prepare()
        self.assertEqual(self.created_dirs,set())

    def test_old21_marker_and_no_private_scope_graphs_supported(self):
        self.assertEqual(len(self.marker['roots']), 21)
        self.prepare()
        self.assertEqual(set(path.name for path in self.scope.iterdir()), {m.storage.MARKER})

    def test_missing_marker_refuses_no_home_mutation(self):
        (self.scope / m.storage.MARKER).unlink()
        with self.assertRaises((ValueError, OSError)): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_marker_numeric_types_are_not_coerced(self):
        self.mutate_json(self.scope / m.storage.MARKER, lambda value: value.update(schemaVersion=True))
        with self.assertRaisesRegex(ValueError, 'marker differs'): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_marker_mismatch_refuses(self):
        self.put(self.scope / m.storage.MARKER, b'{}\n')
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_operator_source_refuses(self):
        self.set_owner(self.bundle, 1000, 1000)
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_source_hash_refuses(self):
        self.put(self.bundle / 'stack.ir.json', b'{}\n')
        with self.assertRaises(ValueError): self.prepare()

    def test_source_provenance_even_rehashed_intent_refuses(self):
        self.put(self.bundle / 'source-provenance.json', b'{}\n')
        self.intent['inputs'] = m.journal.fingerprint(self.bundle); self.write_intents()
        with self.assertRaisesRegex(ValueError, 'provenance'): self.prepare()

    def test_selected_release_must_be_receipt_only(self):
        self.put(self.release / 'bundle.json', b'{}\n')
        with self.assertRaisesRegex(ValueError, 'receipt-only'): self.prepare()

    def test_dual_record_mismatch_refuses(self):
        self.put(self.release / 'installation-receipt.json', p.encoded(dict(self.intent, steps=[])))
        with self.assertRaisesRegex(ValueError, 'bytes differ'): self.prepare()

    def test_metadata_root0755_refuses_no_repair(self):
        self.root.chmod(0o755)
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o755)

    def test_no_fd9_refuses(self):
        os.close(9)
        with self.assertRaises((ValueError, OSError)): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_other_actor_uid_drift_refuses_all7_preflight(self):
        other = next(row for row in self.rows if row['name'] != self.domain)
        self.accounts[other['user']].pw_uid += 1
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_wrong_canonical_home_nss_refuses(self):
        self.actor.pw_dir = '/foreign/home'
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_subid_drift_refuses(self):
        with patch.object(m.storage, 'namespace_root_id', return_value=9000000):
            with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_canonical_offline_refusal_no_mutation(self):
        with patch.object(m.journal, 'assert_domain_offline', side_effect=ValueError('actor not offline')):
            with self.assertRaisesRegex(ValueError, 'not offline'): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_post_offline_intent_cas_refuses(self):
        self.offline.hook = lambda: self.put(self.root / '.install-intent.json', p.encoded(dict(self.intent, steps=[])))
        with self.assertRaisesRegex(ValueError, 'post-offline'): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_post_offline_marker_cas_refuses(self):
        self.offline.hook = lambda: self.put(self.scope / m.storage.MARKER, b'{}\n')
        with self.assertRaisesRegex(ValueError, 'marker CAS'): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_existing_directory_inode_cas_refuses(self):
        self.existing_dirs(); owner = self.owner()
        path = self.home / '.config/containers/systemd'; path.rename(path.with_name('displaced'))
        path.symlink_to(path.with_name('displaced'))
        with self.assertRaises((ValueError, OSError)): owner.run()

    def test_existing_file_samebytes_inode_aba_refuses(self):
        self.existing_files(); owner = self.owner()
        path = self.home / '.config/containers/storage.conf'; body = path.read_bytes(); path.unlink(); self.put(path, body)
        self.set_owner(path, self.actor.pw_uid, self.actor.pw_gid)
        with self.assertRaisesRegex(ValueError, 'CAS'): owner.run()
        self.assertEqual(self.changed_nodes, [])

    def test_mount_cas_refuses(self):
        owner = self.owner(); original = p.mount_id
        with patch.object(p, 'mount_id', side_effect=lambda fd: original(fd) + 1):
            with self.assertRaisesRegex(ValueError, 'CAS'): owner.run()
        self.assertEqual(self.created_dirs, set())

    def previous_current(self):
        old = p.strict((self.old / 'installation-receipt.json').read_bytes())
        old.update(phase='active', steps=['preparing', 'units-selected', 'building', 'starting', 'active'])
        self.put(self.old / 'installation-receipt.json', p.encoded(old))
        self.intent['previousRelease'] = str(self.old); self.write_intents()
        (self.root / 'current').symlink_to('releases/retired')

    def test_previous_root_source_and_current_preserved(self):
        self.previous_current()
        before = (self.old / 'installation-receipt.json').read_bytes()
        proof = self.prepare()
        self.assertEqual(proof['rootCurrent']['target'], 'releases/retired')
        self.assertEqual(os.readlink(self.root / 'current'), 'releases/retired')
        self.assertEqual((self.old / 'installation-receipt.json').read_bytes(), before)

    def test_foreign_current_refuses(self):
        (self.root / 'current').symlink_to('/foreign/release')
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_current_new_release_refuses(self):
        (self.root / 'current').symlink_to(self.release)
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_previous_receipt_schema_boolean_refuses(self):
        self.previous_current()
        self.mutate_json(self.old / 'installation-receipt.json', lambda value: value.update(schemaVersion=True))
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_previous_source_cas_at_offline_boundary_refuses(self):
        self.previous_current()
        self.offline.hook = lambda: self.put(self.old / 'stack.ir.json', b'{}\n')
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_home_path_replacement_refuses(self):
        owner = self.owner()
        moved = self.home.with_name('displaced'); self.home.rename(moved); self.home.symlink_to(moved)
        with self.assertRaises((ValueError, OSError)): owner.run()
        self.assertEqual(self.created_dirs, set())

    def test_released_fd9_refuses(self):
        import fcntl
        fcntl.flock(9, fcntl.LOCK_UN)
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_wrong_fd9_refuses(self):
        wrong = self.root / 'wrong-lock'; self.put(wrong, b'')
        fd = os.open(wrong, os.O_RDONLY)
        try:
            os.dup2(fd, 9)
            with self.assertRaises(ValueError): self.prepare()
        finally: os.close(fd)
        self.assertEqual(self.created_dirs, set())

    def test_last_offline_observation_cannot_hide_config_mutation(self):
        def mutate():
            if len(self.published) == 2:
                path = self.home / '.config/containers/storage.conf'
                body = path.read_bytes(); self.put(path, b'x' + body[1:])
        self.offline.hook = mutate
        with self.assertRaisesRegex(ValueError, 'source bytes'): self.prepare()
        self.assertEqual(set(self.published), {'storage.conf', 'containers.conf'})

    def test_source_special_inode_refuses_without_opening(self):
        os.mkfifo(self.bundle / 'forbidden-fifo')
        with self.assertRaisesRegex(ValueError, 'special inode'): self.prepare()
        self.assertEqual(self.created_dirs, set())

    def test_cli_exact_root_bundle_domain_api(self):
        import contextlib
        import io
        import sys
        output = io.StringIO()
        with patch.object(sys, 'argv', ['prepare-native-account-config.py', '--root', str(self.root), '--bundle', str(self.bundle), '--domain', self.domain]):
            with contextlib.redirect_stdout(output): m.main()
        proof = p.strict(output.getvalue())
        self.assertEqual(proof['domain'], self.domain)
        self.assertEqual(proof['kind'], 'native-account-config')
        self.assertEqual(len(proof['inputFiles']), len(p.INPUTS))

    def test_deadline_refuses(self):
        owner = self.owner(); owner.deadline = 0
        with self.assertRaisesRegex(ValueError, 'deadline'): owner.run()
        self.assertEqual(self.created_dirs, set())


if __name__ == '__main__':
    unittest.main()
