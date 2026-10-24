#!/usr/bin/env python3
"""Real tempfile/FD/openat2 tests; synthetic identities, ACLs and offline lease.

No chown, setfacl, system identity lookup, service query, network or host install.
The production source/provenance, marker, journal, DAG and fingerprint validators
are NOT mocked. These are isolated source tests, not installed/owner acceptance.
"""
import contextlib
import errno
import importlib.util
import io
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).absolute().parents[1] / 'runtime-generator/podman-ops/prepare-native-private-directories.py'
spec = importlib.util.spec_from_file_location('tested_private_directories', SOURCE)
m = importlib.util.module_from_spec(spec)
exec(compile(SOURCE.read_bytes(), str(SOURCE), 'exec'), m.__dict__)
p, o = m.p, m.o


def acl(named=(), group=7, mask=7, other=0):
    rows = [(1, 7, 0xffffffff), *named, (4, group, 0xffffffff),
            (16, mask, 0xffffffff), (32, other, 0xffffffff)]
    return struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *row) for row in rows)


class Directories(unittest.TestCase):
    def test_cli_failure_exposes_code_guard_only_never_exception_values(self):
        output=io.StringIO()
        with patch('sys.argv',['prepare','--bundle','/private/input','--root','/private/state','--domain','platform']), \
             patch.object(m,'prepare',side_effect=ValueError('secret-sentinel /private/key-content')), \
             contextlib.redirect_stderr(output), self.assertRaises(SystemExit) as error:
            m.main()
        self.assertEqual(error.exception.code,1)
        self.assertIn('native private directory preparation refused',output.getvalue())
        self.assertIn('guard: prepare-native-private-directories.py:',output.getvalue())
        self.assertNotIn('secret-sentinel',output.getvalue())
        self.assertNotIn('/private',output.getvalue())
        self.assertNotIn(str(SOURCE.parent),output.getvalue())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='private-directory-model-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'metadata'
        self.bundle = self.base / 'sealed-stage'
        self.release = self.root / 'releases/fresh'
        self.external = self.base / 'mnt/stack'
        self.scope = self.external / 'selected'
        self.domain = 'test-runners'
        self.virtual, self.acls, self.fd_paths = {}, {}, {}
        self.created, self.changed = set(), []
        self.raw_stat, self.raw_lstat, self.raw_fstat = os.stat, os.lstat, os.fstat
        self.raw_open, self.raw_dup = os.open, os.dup
        self.raw_mkdir, self.raw_fchmod = os.mkdir, os.fchmod
        self.operator = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name='operator', pw_dir='/home/operator')
        self.accounts = {'operator': self.operator}
        self.accounts.update({user: SimpleNamespace(pw_uid=uid, pw_gid=uid + 3000, pw_name=user,
            pw_dir='/home/' + user) for uid, user in m.native.IDENTITIES.values()})
        self.groups = {name: SimpleNamespace(gr_name=name, gr_gid=row.pw_gid, gr_mem=[])
                       for name, row in self.accounts.items()}
        self.rows = [dict(name=name, user=user, uid=uid, subuidStart=2883584 + index * 65536,
            services=['runner'] if name == self.domain else [], stateRoot=str(self.scope / 'state' / name),
            graphRoot=str(self.scope / 'graphs' / name), volumeRoot=str(self.scope / 'volumes' / name))
            for index, (name, (uid, user)) in enumerate(m.native.IDENTITIES.items())]
        self.row = next(row for row in self.rows if row['name'] == self.domain)
        self.state = Path(self.row['stateRoot'])
        self.config = dict(root=str(self.scope), dataClass='synthetic')
        self.metadata = dict(schemaVersion=1, deploymentMode='standalone', installerStateRoot=str(self.root),
                             storageScope=self.config, domains=self.rows)
        self.manifest = dict(site='isolated.invalid', deploymentMode='standalone', installerStateRoot=str(self.root),
                             storageScope=self.config)
        self.ir = dict(schemaVersion=1, services={'runner': dict(placement='rootless', rootlessDomain=self.domain,
                       volumes=[])}, volumes={})
        self.mkdir(self.release); self.mkdir(self.scope); self.mkdir(self.bundle)
        self.put(self.root / '.install.lock', b'')
        self.external.chmod(0o2775); self.set_owner(self.external, 1000, 1000)
        self.acls[self.key(self.external)] = (acl([(2, 7, 1000)], other=5), acl([(2, 7, 1000)]))
        self.scope.chmod(0o2770); self.set_owner(self.scope, 1000, 1000)
        actor_entries = [(2, 1, row['uid']) for row in self.rows]
        self.acls[self.key(self.scope)] = (acl([(2, 7, 1000), *actor_entries, (2, 1, 2883584)]),
                                           acl([(2, 7, 1000)]))
        self.intent = dict(schemaVersion=1, phase='preparing', release=str(self.release), previousRelease=None,
                           steps=['preparing'], resumedFrom=None)
        self.reseal()
        self.initial_paths = set(self.base.rglob('*'))
        ancestor_ids = {self.key(path) for path in self.base.parents}
        test = self
        class VirtualStat:
            def __init__(inner, actual):
                inner.actual = actual
                key = actual.st_dev, actual.st_ino
                inner.st_uid, inner.st_gid = test.virtual.get(key, (0, 0))
                inner.st_mode = stat.S_IFDIR | 0o755 if key in ancestor_ids else actual.st_mode
            def __getattr__(inner, key):
                return getattr(inner.actual, key)
        def opened(path, flags, mode=0o777, *, dir_fd=None):
            fd = self.raw_open(path, flags, mode, dir_fd=dir_fd)
            value = Path(os.fsdecode(path))
            self.fd_paths[fd] = value if value.is_absolute() else self.fd_paths[dir_fd] / value
            return fd
        def duplicated(fd):
            other = self.raw_dup(fd); self.fd_paths[other] = self.fd_paths[fd]
            return other
        def mkdir(path, mode=0o777, *, dir_fd=None):
            value = Path(path) if dir_fd is None else self.fd_paths[dir_fd] / path
            self.assertTrue(value.is_relative_to(self.base))
            self.raw_mkdir(path, mode, dir_fd=dir_fd)
            self.created.add(value)
            key = self.key(value)
            parent_key = self.key(value.parent)
            self.virtual[key] = (0, self.virtual.get(parent_key, (0, 0))[1])
            default = self.acls.get(parent_key, (b'', b''))[1]
            if default:
                inherited = bytearray(default)
                for offset in range(4, len(inherited), 8):
                    tag, rights, identifier = struct.unpack('<HHI', inherited[offset:offset + 8])
                    if tag in (16, 32):
                        struct.pack_into('<HHI', inherited, offset, tag, 0, identifier)
                self.acls[key] = bytes(inherited), default
        def chown(fd, uid, gid):
            value = self.fd_paths[fd]
            self.assertIn(value, self.created)
            self.assertNotIn(value, self.initial_paths)
            self.assertEqual(os.listdir(fd), [])
            s = self.raw_fstat(fd); self.virtual[s.st_dev, s.st_ino] = uid, gid
            self.changed.append(('chown', value, uid, gid))
        def chmod(fd, mode):
            value = self.fd_paths[fd]
            self.assertIn(value, self.created)
            self.assertTrue(value.is_relative_to(self.scope))
            self.raw_fchmod(fd, mode)
            self.changed.append(('chmod', value, mode))
        def getacl(fd, name):
            s = self.raw_fstat(fd)
            access, default = self.acls.get((s.st_dev, s.st_ino), (b'', b''))
            return access if name == 'system.posix_acl_access' else default
        def removeacl(fd, name):
            value = self.fd_paths[fd]
            self.assertIn(value, self.created)
            self.assertNotIn(value, self.initial_paths)
            self.assertEqual(os.listdir(fd), [])
            s = self.raw_fstat(fd)
            self.assertEqual(self.virtual[s.st_dev, s.st_ino][0], 0)
            key = s.st_dev, s.st_ino
            access, default = self.acls.get(key, (b'', b''))
            if not (access if name == 'system.posix_acl_access' else default):
                raise OSError(errno.ENODATA, 'fixture has no ACL')
            self.acls[key] = (b'', default) if name == 'system.posix_acl_access' else (access, b'')
            self.changed.append(('removeacl', value, name))
        self.offline = SimpleNamespace(calls=0, hook=None)
        def offline(bundle, domain):
            self.assertEqual((bundle, domain), (self.bundle, self.domain))
            self.offline.calls += 1
            if self.offline.hook:
                self.offline.hook()
            return dict(domain=domain, uid=self.row['uid'], status='offline-preparation-only')
        patches = [patch.object(os, 'stat', side_effect=lambda *a, **kw: VirtualStat(self.raw_stat(*a, **kw))),
            patch.object(os, 'lstat', side_effect=lambda *a, **kw: VirtualStat(self.raw_lstat(*a, **kw))),
            patch.object(os, 'fstat', side_effect=lambda fd: VirtualStat(self.raw_fstat(fd))),
            patch.object(os, 'open', side_effect=opened), patch.object(os, 'dup', side_effect=duplicated),
            patch.object(os, 'mkdir', side_effect=mkdir), patch.object(os, 'fchown', side_effect=chown),
            patch.object(os, 'fchmod', side_effect=chmod), patch.object(os, 'removexattr', side_effect=removeacl),
            patch.object(os, 'geteuid', return_value=0), patch.object(p, 'acl_bytes', side_effect=getacl),
            patch.object(o, 'EXTERNAL_OPERATOR', self.external), patch.object(o, 'lock_held'),
            patch.object(m.journal, 'assert_domain_offline', side_effect=offline),
            patch.object(m.storage, 'namespace_root_id', side_effect=lambda user: next(row['subuidStart'] for row in self.rows if row['user'] == user)),
            patch.object(o.pwd, 'getpwnam', side_effect=lambda name: self.accounts[name]),
            patch.object(o.pwd, 'getpwuid', side_effect=lambda uid: next(row for row in self.accounts.values() if row.pw_uid == uid)),
            patch.object(o.pwd, 'getpwall', side_effect=lambda: list(self.accounts.values())),
            patch.object(o.grp, 'getgrnam', side_effect=lambda name: self.groups[name]),
            patch.object(o.grp, 'getgrgid', side_effect=lambda gid: next(row for row in self.groups.values() if row.gr_gid == gid)),
            patch.object(subprocess, 'run', side_effect=AssertionError('no host operations')),
            patch.object(subprocess, 'Popen', side_effect=AssertionError('no host operations')),
            patch.object(subprocess, 'check_output', side_effect=AssertionError('no host operations'))]
        for item in patches:
            item.start()
        self.addCleanup(patch.stopall)
        real_child = p.child_open
        def child(parent, name, flags):
            fd = real_child(parent, name, flags)
            self.fd_paths[fd] = self.fd_paths[parent] / name
            return fd
        patch.object(p, 'child_open', side_effect=child).start()

    def key(self, path):
        info = self.raw_lstat(path)
        return info.st_dev, info.st_ino

    def set_owner(self, path, uid, gid):
        self.virtual[self.key(path)] = uid, gid

    def mkdir(self, path):
        if not path.exists():
            self.mkdir(path.parent)
            self.raw_mkdir(path, 0o700)

    def put(self, path, value):
        self.mkdir(path.parent)
        path.write_bytes(value); path.chmod(0o600)

    def reseal(self):
        for name, data in [('site/manifest.json', self.manifest), ('podman-domains.json', self.metadata), ('stack.ir.json', self.ir)]:
            self.put(self.bundle / name, p.encoded(data))
        provenance = dict(manifestSha256=p.sha((self.bundle / 'site/manifest.json').read_bytes()))
        self.put(self.bundle / 'source-provenance.json', p.encoded(provenance))
        self.put(self.bundle / 'bundle.json', p.encoded(dict(backend='podman', deploymentMode='standalone',
            sourceProvenanceSha256=p.sha(p.encoded(provenance)), irSha256=p.sha(p.encoded(self.ir)))))
        self.intent['inputs'] = m.journal.fingerprint(self.bundle)
        self.put(self.root / '.install-intent.json', p.encoded(self.intent))
        self.put(self.release / 'installation-receipt.json', p.encoded(self.intent))
        self.marker = dict(schemaVersion=1, kind='standalone-stack-storage', site=self.manifest['site'],
            scope=self.config, domains=sorted([{key: row[key] for key in ('name', 'user', 'uid', *m.KEYS)}
                for row in self.rows], key=lambda row: row['name']), roots=sorted(row[key] for row in self.rows for key in m.KEYS))
        self.put(self.scope / m.storage.MARKER, p.encoded(self.marker))

    def prepare(self):
        return m.prepare(self.bundle, self.domain, self.root)

    def shared(self, name):
        path = self.scope / name
        self.mkdir(path); path.chmod(0o2770); self.set_owner(path, 1000, 1000)
        return path

    def existing_private(self, path):
        if not path.parent.exists():
            self.shared(path.parent.name)
        self.mkdir(path); path.chmod(0o700)
        account = self.accounts[self.row['user']]
        self.set_owner(path, account.pw_uid, account.pw_gid)
        self.initial_paths.add(path)
        return path

    def test_fresh_exact_paths_acl_stripped_only_new_inodes_and_reusable(self):
        scope_before = self.acls[self.key(self.scope)]
        external_before = self.acls[self.key(self.external)]
        intent_before = (self.root / '.install-intent.json').read_bytes()
        proof = self.prepare()
        expected_private = {Path(self.row[key]) for key in m.KEYS} | {self.state / 'releases', self.state / 'runtime-env'}
        expected_shared = {self.scope / name for name in ('state', 'graphs', 'volumes')}
        self.assertEqual(self.created, expected_private | expected_shared)
        self.assertEqual(set(proof['directories']), {str(path) for path in expected_private | expected_shared | {self.scope}})
        for path in expected_private:
            item = proof['directories'][str(path)]
            self.assertEqual((item['uid'], item['gid'], item['mode'], item['acl'], item['defaultAcl']),
                             (self.row['uid'], self.accounts[self.row['user']].pw_gid, 0o700, '', ''))
        for path in expected_shared:
            item = proof['directories'][str(path)]
            self.assertEqual((item['uid'], item['gid'], item['mode'], item['acl'], item['defaultAcl']), (1000, 1000, 0o2770, '', ''))
        self.assertFalse(proof['activationAuthorized'])
        self.assertEqual(self.acls[self.key(self.scope)], scope_before)
        self.assertEqual(self.acls[self.key(self.external)], external_before)
        self.assertEqual((self.root / '.install-intent.json').read_bytes(), intent_before)
        self.assertEqual(list(self.release.iterdir()), [self.release / 'installation-receipt.json'])
        changed = list(self.changed)
        again = self.prepare()
        self.assertTrue(all(not item['created'] for item in again['directories'].values()))
        self.assertEqual(self.changed, changed)
        self.assertGreater(self.offline.calls, 1)

    def test_inherited_defaults_on_each_new_private_leaf_removed(self):
        parent = self.shared('state')
        self.acls[self.key(parent)] = acl([(2, 7, 1000)]), acl([(2, 7, 1000)])
        proof = self.prepare()
        self.assertEqual(proof['directories'][str(self.state)]['defaultAcl'], '')
        self.assertTrue(any(item[:2] == ('removeacl', self.state) for item in self.changed))

    def native_shared_parent(self,name):
        parent=self.shared(name);self.set_owner(parent,0,1000)
        traversal=[(2,1,row['uid']) for row in self.rows]
        self.acls[self.key(parent)]=(acl([(2,7,1000),*traversal]),acl([(2,7,1000)]))
        return parent

    def test_native_root_owned_delegated_shared_parents_preserved_and_private_children_sealed(self):
        parents=[self.native_shared_parent(name) for name in ('state','graphs','volumes')]
        before={parent:(self.virtual[self.key(parent)],self.acls[self.key(parent)]) for parent in parents}
        proof=self.prepare()
        for parent in parents:
            self.assertEqual((self.virtual[self.key(parent)],self.acls[self.key(parent)]),before[parent])
            self.assertFalse(any(item[1]==parent for item in self.changed))
        for key in m.KEYS:
            record=proof['directories'][self.row[key]]
            self.assertEqual((record['uid'],record['mode'],record['acl'],record['defaultAcl']),
                             (self.row['uid'],0o700,'',''))
        self.assertFalse(proof['activationAuthorized'])

    def test_native_root_shared_missing_acl_default_foreign_writer_and_group_refuse(self):
        parent=self.native_shared_parent('state');valid=self.acls[self.key(parent)]
        invalid=[(b'',valid[1]),(valid[0],b''),
                 (acl([(2,7,1000),(2,7,self.rows[0]['uid'])]),valid[1]),
                 (acl([(2,7,1000),(2,1,9999)]),valid[1]),
                 (valid[0],acl([(2,7,1000),(2,1,self.rows[0]['uid'])]))]
        for access,default in invalid:
            self.acls[self.key(parent)]=(access,default)
            with self.subTest(acl=(access.hex(),default.hex())),self.assertRaises(ValueError):self.prepare()
            self.assertEqual(self.created,set());self.assertEqual(self.changed,[])
        self.acls[self.key(parent)]=valid;self.set_owner(parent,0,1001)
        with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(self.created,set())

    def test_native_root_shared_profile_cannot_replace_scope_owner(self):
        self.set_owner(self.scope,0,1000)
        with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(self.created,set())

    def test_old_public_volume_parent_preserved_exactly(self):
        parent = self.shared('volumes'); parent.chmod(0o755); self.set_owner(parent, 0, 1000)
        self.acls[self.key(parent)] = (acl([(2, 7, 1000), *[(2, 1, row['uid']) for row in self.rows]], mask=5, other=5),
                                      acl([(2, 7, 1000)]))
        before = self.acls[self.key(parent)]
        proof = self.prepare()
        self.assertEqual(self.acls[self.key(parent)], before)
        self.assertEqual(proof['directories'][str(parent)]['mode'], 0o755)
        self.assertFalse(any(item[1] == parent for item in self.changed))

    def test_legacy_private_2700_mask_zero_requires_reset_without_changes(self):
        legacy = self.existing_private(self.state); legacy.chmod(0o2700)
        self.acls[self.key(legacy)] = acl([(2, 7, 1000)], mask=0), acl([(2, 7, 1000)])
        before = self.acls[self.key(legacy)]
        with self.assertRaisesRegex(m.Refused, 'complete-clean-reset dependency'):
            self.prepare()
        self.assertEqual(self.changed, []); self.assertEqual(self.created, set())
        self.assertEqual(self.acls[self.key(legacy)], before)
        self.assertEqual(stat.S_IMODE(legacy.stat().st_mode), 0o2700)

    def test_existing_700_named_acl_is_not_repaired(self):
        path = self.existing_private(Path(self.row['graphRoot']))
        self.acls[self.key(path)] = acl([(2, 7, 1000)], mask=0), b''
        with self.assertRaisesRegex(m.Refused, 'complete-clean-reset'):
            self.prepare()
        self.assertEqual(self.changed, [])

    def test_existing_700_default_acl_is_not_repaired(self):
        path = self.existing_private(Path(self.row['volumeRoot']))
        self.acls[self.key(path)] = b'', acl([(2, 7, 1000)])
        with self.assertRaisesRegex(m.Refused, 'complete-clean-reset'):
            self.prepare()
        self.assertEqual(self.changed, [])

    def test_existing_wrong_owner_is_not_chowned(self):
        path = self.existing_private(self.state); self.set_owner(path, 999, 999)
        with self.assertRaisesRegex(m.Refused, 'complete-clean-reset'):
            self.prepare()
        self.assertEqual(self.changed, [])

    def test_existing_populated_correct_private_reused_without_reading_data(self):
        path = self.existing_private(Path(self.row['graphRoot']))
        self.put(path / 'unrelated-data', b'not-read-or-mutated')
        proof = self.prepare()
        self.assertFalse(proof['directories'][str(path)]['created'])
        self.assertEqual((path / 'unrelated-data').read_bytes(), b'not-read-or-mutated')
        self.assertFalse(any(item[1] == path for item in self.changed))

    def test_unsafe_existing_nested_private_child_preflight_before_any_create(self):
        self.existing_private(self.state)
        path = self.existing_private(self.state / 'runtime-env')
        self.acls[self.key(path)] = b'', acl([(2, 7, 1000)])
        with self.assertRaisesRegex(m.Refused, 'complete-clean-reset'):
            self.prepare()
        self.assertEqual(self.created, set())

    def test_foreign_shared_parent_refused(self):
        parent = self.shared('graphs'); self.set_owner(parent, 999, 999)
        with self.assertRaisesRegex(m.Refused, 'shared ancestor'):
            self.prepare()
        self.assertEqual(self.changed, [])

    def test_foreign_shared_default_refused(self):
        parent = self.shared('state')
        self.acls[self.key(parent)] = b'', acl([(2, 7, 999)])
        with self.assertRaisesRegex(m.Refused, 'default ACL'):
            self.prepare()
        self.assertEqual(self.changed, [])

    def test_nonflat_dag_derived_not_hardcoded(self):
        for row in self.rows:
            row['stateRoot'] = str(self.scope / 'storage/private/states' / row['name'])
            row['graphRoot'] = str(self.scope / 'storage/private/engines' / row['name'])
            row['volumeRoot'] = str(self.scope / 'storage/data/vol' / row['name'])
        self.state = Path(self.row['stateRoot']); self.reseal()
        proof = self.prepare()
        self.assertIn(str(self.scope / 'storage/private/engines'), proof['directories'])
        self.assertFalse((self.scope / 'graphs').exists())

    def test_private_shared_alias_refused(self):
        self.row['graphRoot'] = str(self.state / 'engine'); self.reseal()
        with self.assertRaisesRegex(m.Refused, 'DAG overlap'):
            self.prepare()
        self.assertEqual(self.created, set())

    def test_cross_actor_overlap_refused(self):
        other = next(row for row in self.rows if row != self.row)
        other['graphRoot'] = str(self.state / 'nested'); self.reseal()
        with self.assertRaisesRegex(m.Refused, 'DAG overlap'):
            self.prepare()

    def test_scope_escape_refused(self):
        self.row['graphRoot'] = str(self.base / 'foreign'); self.reseal()
        with self.assertRaisesRegex(m.Refused, 'escapes marker scope'):
            self.prepare()
        self.assertEqual(self.created, set())

    def test_selected_domain_required(self):
        with self.assertRaisesRegex(m.Refused, 'unselected domain'):
            m.prepare(self.bundle, 'unselected', self.root)

    def test_marker_mismatch_refused(self):
        self.put(self.scope / m.storage.MARKER, b'{}\n')
        with self.assertRaisesRegex(m.Refused, 'scope marker'):
            self.prepare()
        self.assertEqual(self.changed, [])

    def test_no_marker_no_adoption(self):
        (self.scope / m.storage.MARKER).unlink()
        with self.assertRaises(FileNotFoundError):
            self.prepare()
        self.assertEqual(self.created, set())

    def test_source_hash_mismatch_refused(self):
        self.put(self.bundle / 'stack.ir.json', b'{}\n')
        with self.assertRaisesRegex(m.Refused, 'fingerprint'):
            self.prepare()

    def test_source_provenance_mismatch_despite_new_journal_fingerprint(self):
        self.put(self.bundle / 'source-provenance.json', b'{}\n')
        self.intent['inputs'] = m.journal.fingerprint(self.bundle)
        self.put(self.root / '.install-intent.json', p.encoded(self.intent))
        self.put(self.release / 'installation-receipt.json', p.encoded(self.intent))
        with self.assertRaisesRegex(m.Refused, 'provenance'):
            self.prepare()

    def test_root_metadata_must_be_700(self):
        self.root.chmod(0o755)
        with self.assertRaises(m.Refused):
            self.prepare()

    def test_new_root_release_must_be_700(self):
        self.release.chmod(0o755)
        with self.assertRaises(m.Refused):
            self.prepare()

    def test_new_root_release_must_not_contain_copied_source(self):
        self.put(self.release / 'bundle.json', b'{}\n')
        with self.assertRaisesRegex(m.Refused, 'empty derived receipt leaf'):
            self.prepare()

    def test_root_binding_mismatch_refused(self):
        self.metadata['installerStateRoot'] = str(self.base / 'other'); self.reseal()
        with self.assertRaisesRegex(m.Refused, 'root metadata binding'):
            self.prepare()

    def test_receipt_intent_must_be_byte_identical(self):
        self.put(self.release / 'installation-receipt.json', p.encoded(dict(self.intent, steps=[])))
        with self.assertRaisesRegex(m.Refused, 'receipt/intent bytes'):
            self.prepare()

    def test_non_preparing_intent_refused(self):
        self.intent['phase'] = 'active'; self.reseal()
        with self.assertRaisesRegex(m.Refused, 'preparing intent'):
            self.prepare()

    def test_source_operator_writable_tree_refused(self):
        self.set_owner(self.bundle, 1000, 1000)
        with self.assertRaises(m.Refused):
            self.prepare()
        self.assertEqual(self.changed, [])

    def test_source_nested_operator_owned_file_refused(self):
        path = self.bundle / 'nested/payload'; self.put(path, b'public')
        self.set_owner(path, 1000, 1000)
        with self.assertRaisesRegex(m.Refused, 'root-sealed'):
            self.prepare()

    def test_source_hardlink_refused(self):
        os.link(self.bundle / 'bundle.json', self.bundle / 'alias')
        with self.assertRaisesRegex(m.Refused, 'root-sealed'):
            self.prepare()

    def native_marker(self, gid=1000, uid=1000, mask=0, default=False, access=True):
        marker=self.scope/m.storage.MARKER
        self.set_owner(marker,0,gid)
        rows=((1,6,0xffffffff),(2,7,uid),(4,7,0xffffffff),(16,mask,0xffffffff),(32,0,0xffffffff))
        body=struct.pack('<I',2)+b''.join(struct.pack('<HHI',*row) for row in rows)
        self.acls[self.key(marker)]=(body if access else b'',body if default else b'')
        return marker

    def test_exact_native_private_marker_preserved_during_new_directory_preparation(self):
        marker=self.native_marker();before=(marker.read_bytes(),self.virtual[self.key(marker)],self.acls[self.key(marker)],marker.stat().st_mode)
        result=self.prepare()
        self.assertFalse(result['activationAuthorized'])
        self.assertEqual((marker.read_bytes(),self.virtual[self.key(marker)],self.acls[self.key(marker)],marker.stat().st_mode),before)
        self.assertNotIn(marker,self.created)

    def test_native_operator_gid_private_marker_without_acl_allowed(self):
        self.native_marker(access=False)
        self.assertFalse(self.prepare()['activationAuthorized'])

    def test_native_marker_foreign_gid_named_actor_mask_and_default_acl_refuse_before_mkdir(self):
        for options in ({'gid':1001},{'uid':1001},{'mask':1},{'default':True}):
            with self.subTest(options=options):
                self.native_marker(**options)
                with self.assertRaises(m.Refused):self.prepare()
                self.assertEqual(self.created,set())
                self.assertEqual(self.changed,[])

    def test_operator_gid_is_not_accepted_for_install_intent(self):
        self.native_marker();self.set_owner(self.root/'.install-intent.json',0,1000)
        with self.assertRaisesRegex(m.Refused,'root file group differs'):self.prepare()
        self.assertEqual(self.created,set())

    def test_marker_profile_never_applies_to_same_name_outside_held_scope(self):
        self.native_marker()
        with m_test_preparation(self) as prep:
            other=self.root/m.storage.MARKER;self.put(other,p.encoded(self.marker));self.set_owner(other,0,1000)
            with self.assertRaisesRegex(m.Refused,'root file group differs'):
                prep.read_file(prep.root_fd,m.storage.MARKER,True)

    def test_marker_profile_requires_private_read(self):
        self.native_marker()
        with m_test_preparation(self) as prep:
            with self.assertRaisesRegex(m.Refused,'root file group differs'):
                prep.read_file(prep.fds[self.scope],m.storage.MARKER,False)

    def test_native_marker_raw_acl_cas_cannot_rebase_to_other_allowed_profile(self):
        marker=self.native_marker()
        self.offline.hook=lambda:self.acls.__setitem__(self.key(marker),(b'',b''))
        with self.assertRaisesRegex(m.Refused,'scope marker CAS'):self.prepare()
        self.assertEqual(self.created,set())

    def test_marker_hardlink_refused(self):
        os.link(self.scope / m.storage.MARKER, self.scope / 'alias')
        with self.assertRaises(m.Refused):
            self.prepare()

    def test_source_symlink_refused_before_open(self):
        (self.bundle / 'linked').symlink_to(self.bundle / 'bundle.json')
        with self.assertRaisesRegex(m.Refused, 'symlink or special inode'):
            self.prepare()

    def test_selected_private_symlink_refused_by_real_openat2(self):
        parent = self.shared('graphs')
        (parent / self.domain).symlink_to(self.base)
        with self.assertRaises(OSError):
            self.prepare()
        self.assertEqual(self.changed, [])

    def test_account_drift_refused(self):
        self.accounts[self.row['user']].pw_uid += 1
        with self.assertRaisesRegex(m.Refused, 'account/group'):
            self.prepare()

    def test_subordinate_source_drift_refused(self):
        with patch.object(m.storage, 'namespace_root_id', return_value=9000000):
            with self.assertRaisesRegex(m.Refused, 'subordinate UID/GID'):
                self.prepare()

    def test_root_current_cannot_be_new_release(self):
        (self.root / 'current').symlink_to(self.release)
        with self.assertRaisesRegex(m.Refused, 'current must name only an old release'):
            self.prepare()

    def test_actor_current_must_be_old_actor_release(self):
        self.existing_private(self.state)
        (self.state / 'current').symlink_to(self.release)
        with self.assertRaisesRegex(m.Refused, 'current must name only an old release'):
            self.prepare()

    def test_canonical_offline_refusal_performs_no_mutation(self):
        with patch.object(m.journal, 'assert_domain_offline', side_effect=ValueError('not offline')):
            with self.assertRaisesRegex(ValueError, 'not offline'):
                self.prepare()
        self.assertEqual(self.created, set()); self.assertEqual(self.changed, [])

    def test_canonical_lock_refusal_performs_no_mutation(self):
        with patch.object(o, 'lock_held', side_effect=m.Refused('missing inherited FD9')):
            with self.assertRaisesRegex(m.Refused, 'FD9'):
                self.prepare()
        self.assertEqual(self.changed, [])

    def test_intent_cas_mutation_during_preparation_refused(self):
        def mutate():
            self.put(self.root / '.install-intent.json', p.encoded(dict(self.intent, steps=[])))
        self.offline.hook = mutate
        with self.assertRaisesRegex(m.Refused, 'preparing root record/receipt CAS'):
            self.prepare()
        self.assertEqual(self.created, set())

    def test_marker_cas_mutation_before_first_mkdir_refused(self):
        self.offline.hook = lambda: self.put(self.scope / m.storage.MARKER, b'{}\n')
        with self.assertRaisesRegex(m.Refused, 'scope marker CAS'):
            self.prepare()
        self.assertEqual(self.created, set())

    def test_offline_gate_rechecked_after_creation(self):
        def gate():
            if self.created:
                raise m.Refused('selected actor changed')
        self.offline.hook = gate
        with self.assertRaisesRegex(m.Refused, 'actor changed'):
            self.prepare()
        self.assertTrue(self.created)
        self.assertTrue(all(path.exists() for path in self.created))

    def test_mount_identity_cas_refused(self):
        with m_test_preparation(self) as prep:
            real = p.mount_id
            with patch.object(p, 'mount_id', side_effect=lambda fd: real(fd) + 1):
                with self.assertRaisesRegex(m.Refused, 'CAS changed'):
                    prep.run()
        self.assertEqual(self.created, set())

    def test_inode_aba_source_same_bytes_refused(self):
        with m_test_preparation(self) as prep:
            path = self.bundle / 'bundle.json'; data = path.read_bytes()
            path.unlink(); self.put(path, data)
            with self.assertRaisesRegex(m.Refused, 'source tree CAS'):
                prep.run()
        self.assertEqual(self.created, set())

    def test_deadline_is_fail_closed(self):
        with m_test_preparation(self) as prep:
            prep.deadline = 0
            with self.assertRaisesRegex(m.Refused, 'deadline'):
                prep.run()
        self.assertEqual(self.created, set())

    def test_missing_optional_input_pinned_absent(self):
        proof = self.prepare()
        self.assertIsNone(proof['inputs']['site/agent-vm.json'])
        self.assertIsNone(proof['inputs']['site/global.settings/webservices.sops.json'])

    def test_cas_after_last_offline_observation_cannot_return_proof(self):
        def mutate():
            if len(self.created) == 8:
                self.put(self.root / '.install-intent.json', p.encoded(dict(self.intent, steps=[])))
        self.offline.hook = mutate
        with self.assertRaisesRegex(m.Refused, 'preparing root record/receipt CAS'):
            self.prepare()
        self.assertEqual(len(self.created), 8)

    def test_source_special_inode_refused_without_opening(self):
        os.mkfifo(self.bundle / 'fifo')
        with self.assertRaisesRegex(m.Refused, 'special inode'):
            self.prepare()
        self.assertEqual(self.created, set())

    def test_source_group_writable_file_refused(self):
        (self.bundle / 'bundle.json').chmod(0o660)
        with self.assertRaisesRegex(m.Refused, 'root-sealed'):
            self.prepare()

    def test_root_metadata_acl_refused(self):
        self.acls[self.key(self.root)] = acl([(2, 7, 1000)], mask=0), b''
        with self.assertRaisesRegex(m.Refused, 'ACL'):
            self.prepare()

    def test_source_default_acl_refused(self):
        self.acls[self.key(self.bundle / 'site')] = b'', acl([(2, 7, 1000)])
        with self.assertRaisesRegex(m.Refused, 'root-sealed'):
            self.prepare()

    def test_operator_group_foreign_writer_refused(self):
        self.groups['operator'].gr_mem = ['foreign']
        with self.assertRaisesRegex(m.Refused, 'foreign writer'):
            self.prepare()

    def test_service_membership_mismatch_refused(self):
        self.row['services'] = []; self.reseal()
        with self.assertRaisesRegex(m.Refused, 'service membership'):
            self.prepare()

    def test_source_absent_pin_cannot_appear(self):
        with m_test_preparation(self) as prep:
            self.put(self.bundle / 'site/components.lock.json', b'{}\n')
            with self.assertRaisesRegex(m.Refused, 'source tree CAS'):
                prep.run()
        self.assertEqual(self.created, set())

    def test_scope_default_acl_cas_preserved_not_unmasked(self):
        with m_test_preparation(self) as prep:
            key = self.key(self.scope)
            access, default = self.acls[key]
            self.acls[key] = access, acl([(2, 6, 1000)], group=6, mask=6)
            with self.assertRaisesRegex(m.Refused, 'scope inode/mount/ACL CAS'):
                prep.run()
            self.assertNotEqual(self.acls[key][1], default)
        self.assertEqual(self.changed, [])

    def test_root_current_aba_same_target_refused(self):
        self.existing_private(self.state)
        (self.state / 'current').symlink_to('releases/old')
        with m_test_preparation(self) as prep:
            (self.state / 'current').unlink()
            (self.state / 'current').symlink_to('releases/old')
            with self.assertRaisesRegex(m.Refused, 'CAS changed'):
                prep.run()
        self.assertEqual(self.created, set())

    def test_source_depth_bound_refused(self):
        self.put(self.bundle / Path(*(['deep'] * 49)) / 'file', b'bounded')
        with self.assertRaisesRegex(m.Refused, 'bound'):
            self.prepare()
        self.assertEqual(self.changed, [])

    def test_previous_root_and_actor_current_retained(self):
        old = self.root / 'releases/old'
        self.mkdir(old)
        for name, digest in self.intent['inputs'].items():
            if digest is not None:
                self.put(old / name, (self.bundle / name).read_bytes())
        self.put(old / 'installation-receipt.json', p.encoded(dict(self.intent, release=str(old), phase='active')))
        self.intent['previousRelease'] = str(old)
        self.reseal()
        (self.root / 'current').symlink_to(old)
        self.existing_private(self.state)
        (self.state / 'current').symlink_to('releases/old')
        proof = self.prepare()
        self.assertEqual(proof['previousRelease'], str(old))
        self.assertEqual(os.readlink(self.root / 'current'), str(old))
        self.assertEqual(os.readlink(self.state / 'current'), 'releases/old')
        self.assertFalse(proof['activationAuthorized'])

    def test_previous_receipt_change_refused(self):
        old = self.root / 'releases/old'
        self.mkdir(old)
        for name, digest in self.intent['inputs'].items():
            if digest is not None:
                self.put(old / name, (self.bundle / name).read_bytes())
        self.put(old / 'installation-receipt.json', p.encoded(dict(self.intent, release=str(old), phase='active')))
        self.intent['previousRelease'] = str(old); self.reseal()
        (self.root / 'current').symlink_to(old)
        with m_test_preparation(self) as prep:
            self.put(old / 'installation-receipt.json', p.encoded(dict(self.intent, release=str(old), phase='failed')))
            with self.assertRaisesRegex(m.Refused, 'active receipt'):
                prep.run()
        self.assertEqual(self.created, set())


class m_test_preparation:
    def __init__(self, test):
        self.prep = m.Preparation(test.bundle, test.domain, test.root)
    def __enter__(self):
        return self.prep
    def __exit__(self, *unused):
        self.prep.close()


if __name__ == '__main__':
    unittest.main()
