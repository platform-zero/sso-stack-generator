#!/usr/bin/env python3
"""Isolated FD/UID/ACL model tests; no installation, service calls or chown.

Real file operations are confined to TemporaryDirectory. Root/account/ACL/mount
identities and canonical inactive/lock observations are synthetic. The production
adapter and projector run together, without compatibility/permission shims.
"""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).absolute().parents[1] / 'runtime-generator/podman-ops/native-runtime-projection-owner.py'
spec = importlib.util.spec_from_file_location('projection_owner_tested', SOURCE)
o = importlib.util.module_from_spec(spec)
exec(compile(SOURCE.read_bytes(), str(SOURCE), 'exec'), o.__dict__)
p = o.p


def acl(named=(), *, other=0, group=7, mask=7):
    rows = [(1, 7, 0xffffffff), *named, (4, group, 0xffffffff),
            (16, mask, 0xffffffff), (32, other, 0xffffffff)]
    return struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *row) for row in rows)


class Owner(unittest.TestCase):
    external = False
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='projection-owner-model-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.install = self.base / 'metadata'
        self.release = self.install / 'releases/fresh'
        self.external_parent = self.base / 'mnt/stack'
        self.scope = (self.external_parent if self.external else self.base) / 'scope'
        self.operator = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name='gerald', pw_dir='/home/gerald')
        self.accounts = {user: SimpleNamespace(pw_name=user, pw_uid=uid, pw_gid=uid + 3000,
                                               pw_dir='/home/' + user)
                         for uid, user in o.native.IDENTITIES.values()}
        self.accounts['gerald'] = self.operator
        self.groups = {user: SimpleNamespace(gr_name=user, gr_gid=account.pw_gid, gr_mem=[])
                       for user, account in self.accounts.items()}
        self.virtual, self.acls, self.fd_paths, self.mutations = {}, {}, {}, []
        self.domain = 'test-runners'
        self.scope_config = dict(root=str(self.scope), dataClass='synthetic')
        self.rows = []
        for name, (uid, user) in o.native.IDENTITIES.items():
            row = dict(name=name, uid=uid, user=user, services=[],
                       stateRoot=str(self.scope / 'state' / name),
                       graphRoot=str(self.scope / 'graph' / name),
                       volumeRoot=str(self.scope / 'volumes' / name))
            self.rows.append(row)
            for key in ('stateRoot', 'graphRoot', 'volumeRoot'):
                self.mkdir(Path(row[key])); self.set_owner(Path(row[key]), uid, uid + 3000)
        self.row = next(row for row in self.rows if row['name'] == self.domain)
        self.row['services'] = ['runner80', 'test-runner']
        next(row for row in self.rows if row['name'] == 'platform')['services'] = ['other']
        self.state = Path(self.row['stateRoot']); self.slot = self.state / 'releases/fresh'
        self.mkdir(self.slot)
        self.set_owner(self.state / 'releases', self.row['uid'], self.accounts[self.row['user']].pw_gid)
        self.destination = self.slot / 'runtime'
        self.manifest = dict(site='synthetic.invalid', deploymentMode='standalone', storageScope=self.scope_config)
        self.metadata = dict(schemaVersion=1, deploymentMode='standalone', installerStateRoot=str(self.install),
                             storageScope=self.scope_config, domains=self.rows)
        self.ir = {'services': {
            'test-runner': {'placement': 'rootless', 'rootlessDomain': self.domain,
                            'environment': {'DOMAIN': '${DOMAIN}'}, 'volumes': []},
            'runner80': {'placement': 'rootless', 'rootlessDomain': self.domain,
                         'environment': {'RUNNER_TOKEN': '${RUNNER80_TOKEN}'},
                         'volumes': ['./configs/app:/etc/app:ro'], 'userns': 'keep-id'},
            'other': {'placement': 'rootless', 'rootlessDomain': 'platform',
                      'environment': {'OTHER_TOKEN': '${OTHER_TOKEN}'}, 'volumes': []}}}
        self.put(self.release / 'bundle.json', b'{}\n')
        self.put(self.release / 'source-provenance.json', b'{}\n')
        self.put(self.release / 'runtime/stack.env', b'DOMAIN=synthetic.invalid\nRUNNER80_TOKEN=selected-token\n'
                 b'OTHER_TOKEN=other-secret-sentinel\nP0_DERIVATION_MASTER_KEY=root-master-sentinel\n')
        self.put(self.release / 'runtime/configs/app/public.json', b'{"operational":true}\n')
        self.put(self.release / 'runtime/configs/app/script.sh', b'#!/bin/sh\nexit 0\n')
        self.mkdir(self.release / 'runtime/configs/app/empty')
        self.put(self.release / 'runtime/configs/unselected/private', b'other-secret-sentinel')
        self.put(self.release / 'build/selected/source.sh', b'#!/bin/sh\ntrue\n')
        self.put(self.slot / 'build/selected/source.sh', b'#!/bin/sh\ntrue\n')
        self.put(self.install / '.install.lock', b'')
        for node in (self.scope, self.scope / 'state', self.scope / 'graph', self.scope / 'volumes'):
            node.chmod(0o2770); self.set_owner(node, 1000, 1000)
            self.acls[self.key(node)] = (acl([(2, 7, 1000),
                *[(2, 1, row['uid']) for row in self.rows], (2, 1, 2883584)]), b'')
        self.acls[self.key(self.scope)] = (self.acls[self.key(self.scope)][0],
            acl([(2, 6, 1000), (8, 6, 1000)], group=6, mask=6))
        if self.external:
            self.external_parent.chmod(0o2775); self.set_owner(self.external_parent, 1000, 1000)
            exact = acl([(2, 7, 1000), (8, 7, 1000)], other=5)
            self.acls[self.key(self.external_parent)] = exact, acl([(2, 7, 1000)], other=0)
        self.reseal()
        self.raw_fstat, self.raw_stat, self.raw_lstat = os.fstat, os.stat, os.lstat
        self.raw_open, self.raw_dup, self.raw_chmod = os.open, os.dup, os.fchmod
        test = self
        class VirtualStat:
            def __init__(inner, actual):
                inner.actual = actual
                inner.st_uid, inner.st_gid = test.virtual.get((actual.st_dev, actual.st_ino), (0, 0))
                inner.st_mode = actual.st_mode
                # Non-root /tmp is an explicitly synthetic ancestor model, not
                # production's actual ancestry or a bypass option.
                if (actual.st_dev, actual.st_ino) in test.ancestor_ids:
                    inner.st_mode = stat.S_IFDIR | 0o755
            def __getattr__(inner, name):
                return getattr(inner.actual, name)
        self.ancestor_ids = {self.key(node) for node in self.base.parents}
        def opened(path, flags, mode=0o777, *, dir_fd=None):
            fd = self.raw_open(path, flags, mode, dir_fd=dir_fd)
            value = Path(os.fsdecode(path))
            if not value.is_absolute():
                value = self.fd_paths.get(dir_fd, Path.cwd()) / value
            self.fd_paths[fd] = value
            return fd
        def duplicated(fd):
            result = self.raw_dup(fd)
            self.fd_paths[result] = self.fd_paths.get(fd)
            return result
        def chown(fd, uid, gid):
            path = self.fd_paths.get(fd)
            self.assertIsNotNone(path)
            self.assertTrue(path.is_relative_to(self.base))
            self.assertTrue(path == self.slot or path.is_relative_to(self.destination))
            actual = self.raw_fstat(fd)
            self.virtual[actual.st_dev, actual.st_ino] = uid, gid
            self.mutations.append((path, uid, gid))
        def chmod(fd, mode):
            path = self.fd_paths.get(fd)
            self.assertIsNotNone(path)
            self.assertTrue(path.is_relative_to(self.base))
            self.raw_chmod(fd, mode)
        def getacl(fd, name):
            actual = self.raw_fstat(fd)
            access, default = self.acls.get((actual.st_dev, actual.st_ino), (b'', b''))
            return access if name == 'system.posix_acl_access' else default
        def entries(path, **unused):
            # safe_parent itself is real; only getfacl output is modelled.
            body = self.acls.get(self.key(path), (b'', b''))[0]
            result = {}
            for (tag, identifier), rights in o.acl_entries(body).items():
                kind = {1: 'user', 2: 'user', 4: 'group', 8: 'group', 16: 'mask', 32: 'other'}[tag]
                name = '' if identifier == 0xffffffff else next((a.pw_name for a in self.accounts.values()
                        if a.pw_uid == identifier), str(identifier))
                result[kind, name] = ''.join(c if rights & bit else '-' for c, bit in zip('rwx', (4, 2, 1)))
            return result
        patches = [patch.object(os, 'fstat', side_effect=lambda fd: VirtualStat(self.raw_fstat(fd))),
                   patch.object(os, 'stat', side_effect=lambda *a, **kw: VirtualStat(self.raw_stat(*a, **kw))),
                   patch.object(os, 'lstat', side_effect=lambda *a, **kw: VirtualStat(self.raw_lstat(*a, **kw))),
                   patch.object(os, 'open', side_effect=opened), patch.object(os, 'dup', side_effect=duplicated),
                   patch.object(os, 'fchown', side_effect=chown), patch.object(os, 'fchmod', side_effect=chmod),
                   patch.object(os, 'geteuid', return_value=0), patch.object(p, 'acl_bytes', side_effect=getacl),
                   patch.object(p, 'mount_id', return_value=91),
                   patch.object(o, 'EXTERNAL_OPERATOR', self.external_parent),
                   patch.object(o, 'lock_held'), patch.object(o, 'inactive'),
                   patch.object(o.storage, 'authority', return_value=(self.scope, self.operator, self.marker)),
                   patch.object(o.storage, 'marker'), patch.object(o.storage, 'entries', side_effect=entries),
                   patch.object(o.storage, 'namespace_root_id', side_effect=lambda user: 2883584
                                + (self.accounts[user].pw_uid - 780) * 65536),
                   patch.object(pwd_lookup := o.pwd, 'getpwnam', side_effect=lambda user: self.accounts[user]),
                   patch.object(pwd_lookup, 'getpwuid', side_effect=lambda uid: next(a for a in self.accounts.values() if a.pw_uid == uid)),
                   patch.object(pwd_lookup, 'getpwall', side_effect=lambda: list(self.accounts.values())),
                   patch.object(o.grp, 'getgrnam', side_effect=lambda name: self.groups[name]),
                   patch.object(o.grp, 'getgrgid', side_effect=lambda gid: next(g for g in self.groups.values() if g.gr_gid == gid))]
        for mocked in patches:
            mocked.start()
        self.addCleanup(patch.stopall)
        self.addCleanup(self.close_sessions)
        # The real openat2 syscall returns an FD outside os.open; register paths
        # solely for the fixture's no-privileged-chown guard.
        real_child = p.child_open
        def child(parent, name, flags):
            fd = real_child(parent, name, flags)
            self.fd_paths[fd] = self.fd_paths[parent] / name
            return fd
        patch.object(p, 'child_open', side_effect=child).start()

    def close_sessions(self):
        for session in o._sessions.values():
            session.close()
        o._sessions.clear()

    def key(self, path):
        s = path.lstat()
        return s.st_dev, s.st_ino

    def set_owner(self, path, uid, gid):
        self.virtual[self.key(path)] = uid, gid

    def mkdir(self, path):
        if not path.exists():
            self.mkdir(path.parent); path.mkdir(mode=0o700)

    def put(self, path, body):
        self.mkdir(path.parent); path.write_bytes(body); path.chmod(0o600)

    def reseal(self):
        for name, value in [('stack.ir.json', self.ir), ('podman-domains.json', self.metadata),
                            ('site/manifest.json', self.manifest)]:
            self.put(self.release / name, p.encoded(value))
        self.marker = dict(schemaVersion=1, kind='standalone-stack-storage', site=self.manifest['site'],
                           scope=self.scope_config, domains=sorted([{k: row[k] for k in
                           ('name', 'user', 'uid', 'stateRoot', 'graphRoot', 'volumeRoot')} for row in self.rows],
                           key=lambda row: row['name']),
                           roots=sorted(row[k] for row in self.rows for k in ('stateRoot', 'graphRoot', 'volumeRoot')))
        self.put(self.scope / '.stack-installation.json', p.encoded(self.marker))
        self.prior = dict(schemaVersion=1, phase='preparing', release=str(self.release), previousRelease=None,
                          inputs={name: p.sha((self.release / name).read_bytes()) if (self.release / name).exists()
                                  else None for name in p.INPUTS}, steps=['preparing'])
        self.write_records(self.prior)

    def write_records(self, value):
        self.put(self.install / '.install-intent.json', p.encoded(value))
        self.put(self.release / 'installation-receipt.json', p.encoded(value))

    def prepare(self):
        self.custody = o.prepare_custody(self.install, self.release, self.prior, self.domain)
        return self.custody

    def publish(self):
        self.new = dict(self.prior, projectionCustody=self.custody)
        self.write_records(self.new)

    def run_owner(self):
        return o.project_and_handoff(self.install, self.release, self.new, self.domain)

    def test_exact_schema_and_no_journal_write(self):
        before = (self.install / '.install-intent.json').read_bytes()
        custody = self.prepare()
        self.assertEqual(set(custody), {'schemaVersion', 'selection', 'operatorUid', 'operatorGid', 'actorGid', 'directories', 'current'})
        self.assertEqual(before, (self.install / '.install-intent.json').read_bytes())
        self.assertFalse(self.destination.exists()); self.assertEqual(self.mutations, [])
        self.assertTrue(o.lock_held.called); self.assertTrue(o.storage.authority.called)

    def test_real_projector_fd_handoff_scoped_public_private_modes(self):
        self.prepare(); self.publish(); proof = self.run_owner()
        self.assertFalse(proof['activationAuthorized'])
        self.assertEqual(proof['environmentHandoff']['status'], 'canonical-owner-copy-required')
        self.assertEqual(set(proof['environmentHandoff']['files']), {'test-runner.env', 'runner80.env'})
        self.assertTrue(proof['environmentHandoff']['ensurePrivateStores'])
        self.assertFalse((self.destination / 'stack.env').exists())
        self.assertEqual((self.destination / 'service-env/test-runner.env').read_text(), 'DOMAIN=synthetic.invalid\n')
        self.assertEqual((self.destination / 'service-env/runner80.env').read_text(), 'RUNNER_TOKEN=selected-token\n')
        for path, mode in [(self.slot, 0o700), (self.destination, 0o700),
                           (self.destination / 'configs', 0o755), (self.destination / 'configs/app', 0o755),
                           (self.destination / 'configs/app/empty', 0o755),
                           (self.destination / 'configs/app/public.json', 0o644),
                           (self.destination / 'configs/app/script.sh', 0o755),
                           (self.destination / 'service-env', 0o700),
                           (self.destination / 'service-env/test-runner.env', 0o600)]:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
            self.assertEqual(path.stat().st_uid, self.row['uid'])
        self.assertEqual((self.slot / 'build/selected/source.sh').stat().st_uid, 0)
        for path in self.destination.rglob('*'):
            if path.is_file():
                self.assertNotIn(b'root-master-sentinel', path.read_bytes())
                self.assertNotIn(b'other-secret-sentinel', path.read_bytes())
        self.assertEqual(self.mutations[-1][0], self.slot)

    def test_no_fd_custody_adoption_between_processes(self):
        self.new = dict(self.prior)
        with self.assertRaisesRegex(ValueError, 'same-process'):
            self.run_owner()

    def test_full_input_set_required(self):
        self.prior['inputs'].pop('site/agent-vm.json'); self.write_records(self.prior)
        with self.assertRaisesRegex(ValueError, 'full installation'):
            self.prepare()

    def test_receipt_and_intent_must_equal_bytes(self):
        self.put(self.release / 'installation-receipt.json', p.encoded(self.prior).rstrip())
        with self.assertRaisesRegex(ValueError, 'CAS'):
            self.prepare()

    def test_wrong_actor_table(self):
        self.accounts[self.row['user']].pw_uid += 1
        with self.assertRaises(ValueError): self.prepare()

    def test_foreign_operator_group_writer(self):
        self.groups['gerald'].gr_mem = ['foreign']
        with self.assertRaisesRegex(ValueError, 'foreign writer'): self.prepare()

    def test_actor_gid_change_after_prepare(self):
        self.prepare(); self.publish(); self.accounts[self.row['user']].pw_gid += 1
        with self.assertRaises(ValueError): self.run_owner()
        self.assertFalse(self.destination.exists())

    def test_root_source_release_private(self):
        self.release.chmod(0o755)
        with self.assertRaises(ValueError): self.prepare()

    def test_new_actor_release_must_be_root_private(self):
        self.set_owner(self.slot, self.row['uid'], self.row['uid'] + 3000)
        with self.assertRaises(ValueError): self.prepare()

    def test_symlink_selected_graph_refused(self):
        graph = Path(self.row['graphRoot']); graph.rename(graph.with_name('moved')); graph.symlink_to(graph.with_name('moved'))
        with self.assertRaises(OSError): self.prepare()

    def test_hardlinked_marker_refused(self):
        os.link(self.scope / '.stack-installation.json', self.scope / 'alias')
        with self.assertRaises(ValueError): self.prepare()

    def test_actor_write_acl_and_mask_refused(self):
        self.acls[self.key(self.scope)] = acl([(2, 3, self.row['uid'])]), b''
        with self.assertRaises(ValueError): self.prepare()

    def test_default_acl_inside_scope_refused(self):
        self.acls[self.key(self.scope)] = (self.acls[self.key(self.scope)][0], acl())
        with self.assertRaises(ValueError): self.prepare()

    def test_scope_operator_only_default_acl_preserved_through_real_handoff(self):
        before = self.acls[self.key(self.scope)]
        self.prepare(); self.publish(); self.run_owner()
        self.assertEqual(self.acls[self.key(self.scope)], before)
        self.assertTrue(before[1])
        self.assertNotIn(self.scope, [path for path, _, _ in self.mutations])

    def test_foreign_default_acl_writer_refused_even_if_pinned(self):
        access, _ = self.acls[self.key(self.scope)]
        self.acls[self.key(self.scope)] = access, acl([(2, 6, 1001), (8, 6, 1000)], group=6, mask=6)
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(self.mutations)

    def test_scope_default_acl_change_during_projection_is_refused(self):
        key = self.key(self.scope)
        self.race(lambda: self.acls.__setitem__(key, (self.acls[key][0], b'')))

    def test_actor_root_default_acl_is_never_allowed(self):
        self.acls[self.key(self.state)] = b'', acl([(2, 6, 1000), (8, 6, 1000)], group=6, mask=6)
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(self.mutations)

    def test_fresh_release_default_acl_is_never_allowed(self):
        self.acls[self.key(self.slot)] = b'', acl([(2, 6, 1000), (8, 6, 1000)], group=6, mask=6)
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(self.mutations)

    def test_root_master_copied_into_public_build_is_refused(self):
        for base in (self.release, self.slot):
            self.put(base / 'build/selected/leak', b'root-master-sentinel')
        self.prepare(); self.publish()
        with self.assertRaisesRegex(ValueError, 'root-only'): self.run_owner()
        self.assertFalse(self.destination.exists()); self.assertFalse(self.mutations)

    def test_aggregate_runner_build_file_refused(self):
        self.put(self.slot / 'build/.env', b'DOMAIN=synthetic.invalid')
        with self.assertRaisesRegex(ValueError, 'aggregate'): self.prepare()

    def test_unrelated_actor_public_copy_refused(self):
        self.put(self.slot / 'site/global.settings/webservices.sops.json', b'synthetic')
        with self.assertRaises(ValueError): self.prepare()

    def test_same_transaction_only_custody_field_may_change(self):
        self.prepare(); self.publish(); self.new['extra'] = True; self.write_records(self.new)
        with self.assertRaisesRegex(ValueError, 'beyond'): self.run_owner()
        self.assertFalse(self.destination.exists())

    def test_custody_return_not_mutable_authority(self):
        self.prepare(); self.custody['actorGid'] += 1; self.publish()
        with self.assertRaises(ValueError): self.run_owner()

    def test_root_current_not_yet_selected_and_actor_old_or_absent(self):
        (self.state / 'current').symlink_to('releases/old')
        self.prepare(); self.publish(); self.run_owner()
        self.assertEqual(os.readlink(self.state / 'current'), 'releases/old')

    def test_root_current_prior_binding(self):
        (self.install / 'current').symlink_to(str(self.install / 'releases/old'))
        self.prior['previousRelease'] = str(self.install / 'releases/old'); self.write_records(self.prior)
        self.prepare(); self.publish(); self.run_owner()

    def test_current_cannot_already_select_fresh_release(self):
        (self.state / 'current').symlink_to('releases/fresh')
        with self.assertRaises(ValueError): self.prepare()

    def race(self, mutation, *, at_handoff=False):
        self.prepare(); self.publish()
        target = 'fchown' if at_handoff else 'write_file'
        owner = os if at_handoff else p
        original = getattr(owner, target); called = False
        def raced(*args, **kwargs):
            nonlocal called
            result = original(*args, **kwargs)
            if not called:
                called = True; mutation()
            return result
        with patch.object(owner, target, side_effect=raced):
            with self.assertRaises((ValueError, OSError)): self.run_owner()
        self.assertNotIn(self.slot, [x[0] for x in self.mutations])
        self.assertEqual(self.slot.stat().st_uid, 0)
        self.assertEqual(stat.S_IMODE(self.slot.stat().st_mode), 0o700)

    def test_prepublication_cas_race_leaves_root_private_stage(self):
        self.race(lambda: self.put(self.install / '.install-intent.json', b'{}\n'))
        self.assertFalse(self.destination.exists())
        self.assertTrue(any(x.name.startswith('.domain-projection-') for x in self.slot.iterdir()))

    def test_before_handoff_current_pointer_race(self):
        self.race(lambda: (self.state / 'current').symlink_to('releases/old'), at_handoff=True)

    def test_handoff_source_content_race(self):
        self.race(lambda: self.put(self.release / 'runtime/configs/app/public.json', b'changed'), at_handoff=True)

    def test_handoff_lease_loss(self):
        self.race(lambda: setattr(o.inactive, 'side_effect', o.Refused('synthetic inactive lease loss')), at_handoff=True)

    def test_handoff_projected_file_race(self):
        self.race(lambda: self.put(self.destination / 'service-env/test-runner.env', b'changed'), at_handoff=True)

    def test_handoff_unsealed_extra_child_race(self):
        self.race(lambda: self.put(self.destination / 'service-env/foreign.env', b'foreign'), at_handoff=True)

    def test_wrong_actor_handoff_is_not_adopted_as_expected_metadata(self):
        self.prepare(); self.publish()
        original = os.fchown
        with patch.object(os, 'fchown', side_effect=lambda fd, uid, gid: original(fd, uid + 1, gid)):
            with self.assertRaisesRegex(ValueError, 'actor inode handoff'):
                self.run_owner()
        self.assertEqual(self.slot.stat().st_uid, 0)

    def test_acl_added_during_handoff_refused(self):
        def inject():
            self.acls[self.key(self.destination / 'configs/app/public.json')] = acl([(2, 7, 9999)]), b''
        self.race(inject, at_handoff=True)

    def test_scope_entry_mount_boundary_has_no_plain_open_fallback(self):
        original = p.child_open
        def mounted(parent, name, flags):
            if name == self.scope.name:
                raise OSError(18, 'synthetic EXDEV scope entry')
            return original(parent, name, flags)
        with patch.object(p, 'child_open', side_effect=mounted):
            with self.assertRaises(OSError): self.prepare()
        self.assertFalse(self.mutations)

    def test_mapped_root_table_change_after_prepare_refused(self):
        self.prepare(); self.publish(); o.storage.namespace_root_id.side_effect = lambda user: 70000000
        with self.assertRaisesRegex(ValueError, 'mapped namespace'):
            self.run_owner()
        self.assertFalse(self.destination.exists())

    def test_projected_symlink_race_refused(self):
        def replace():
            path = self.destination / 'service-env/test-runner.env'
            path.rename(path.with_name('old.env'))
            path.symlink_to('old.env')
        self.race(replace, at_handoff=True)

    def test_projected_hardlink_race_refused(self):
        self.race(lambda: os.link(self.destination / 'service-env/test-runner.env',
                                 self.destination / 'service-env/alias.env'), at_handoff=True)

    def test_fresh_release_rename_race_never_hands_off_replacement(self):
        moved = self.slot.with_name('moved')
        def replace():
            self.slot.rename(moved); self.mkdir(self.slot)
        self.race(replace)
        self.assertEqual(moved.stat().st_uid, 0)
        self.assertFalse((moved / 'runtime').exists())

    def test_existing_failed_private_stage_not_adopted_or_deleted(self):
        old_stage = self.slot / ('.domain-projection-' + 'a' * 32)
        self.put(old_stage / 'evidence', b'preserved')
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual((old_stage / 'evidence').read_bytes(), b'preserved')

    def test_post_leaf_cas_loss_returns_no_proof_and_never_restarts_or_cleans(self):
        self.prepare(); self.publish()
        original = os.fchown
        def lose_after_last(fd, uid, gid):
            original(fd, uid, gid)
            if self.fd_paths[fd] == self.slot:
                self.put(self.install / '.install-intent.json', b'{}\n')
        with patch.object(os, 'fchown', side_effect=lose_after_last):
            with self.assertRaisesRegex(ValueError, 'CAS'):
                self.run_owner()
        # A post-chown failure is NOT rollback. Preserve exact inert actor0700
        # evidence for the canonical journal; never claim it remains root-owned.
        self.assertEqual(self.slot.stat().st_uid, self.row['uid'])
        self.assertEqual(stat.S_IMODE(self.slot.stat().st_mode), 0o700)
        self.assertTrue(self.destination.exists())
        self.assertEqual((self.install / '.install-intent.json').read_bytes(), b'{}\n')

    def test_inode_identical_input_replacement_refused(self):
        self.prepare(); self.publish()
        path = self.release / 'bundle.json'; body = path.read_bytes(); path.rename(path.with_name('old-bundle'))
        self.put(path, body)
        with self.assertRaisesRegex(ValueError, 'inode'): self.run_owner()

    def empty_domain(self):
        self.ir['services'] = {key: value for key, value in self.ir['services'].items()
                               if value.get('rootlessDomain') != self.domain}
        self.row['services'] = []
        self.reseal()

    def test_empty_domain_real_projector_never_reads_secret_sources(self):
        self.empty_domain(); self.prepare(); self.publish()
        original_subtree = p.subtree
        @contextlib.contextmanager
        def no_runtime(root, name):
            self.assertFalse(root == self.release and name.startswith('runtime'))
            with original_subtree(root, name) as fd:
                yield fd
        with patch.object(p, 'subtree', side_effect=no_runtime), \
                patch.object(p, 'owner_import_material', side_effect=AssertionError('empty domain read owner secret')), \
                patch.object(p, 'env_values', side_effect=AssertionError('empty domain read aggregate env')), \
                patch.object(p, 'root_only', side_effect=AssertionError('empty domain queried master keys')):
            proof = self.run_owner()
        self.assertEqual(proof['files'], {})
        self.assertIsNone(proof['aggregateSha256'])
        self.assertNotIn('aggregateSha256', p.strict((self.destination / 'projection.json').read_bytes()))
        self.assertEqual(proof['environmentHandoff']['files'], {})
        self.assertTrue(proof['environmentHandoff']['ensurePrivateStores'])
        self.assertEqual(set(x.name for x in self.destination.iterdir()), {'configs', 'service-env', 'projection.json'})
        self.assertEqual(self.destination.stat().st_uid, self.row['uid'])

    def test_empty_domain_real_projector_retains_cas_gate(self):
        self.empty_domain()
        self.race(lambda: self.put(self.install / '.install-intent.json', b'{}\n'))
        self.assertFalse(self.destination.exists())

    def test_scope_parent_hook_bind_refusal_never_falls_back(self):
        self.prepare(); self.publish()
        with patch.object(o.Session, 'open_scope_parent', side_effect=o.Refused('synthetic hook refusal')) as hook:
            with self.assertRaisesRegex(ValueError, 'hook refusal'):
                self.run_owner()
        hook.assert_called_once_with(self.scope)
        self.assertFalse(self.destination.exists()); self.assertFalse(self.mutations)

    def test_scope_parent_hook_recheck_refusal_never_hands_off(self):
        self.prepare(); self.publish()
        original = o.Session.open_scope_parent
        calls = []
        @contextlib.contextmanager
        def fail_recheck(session, scope):
            calls.append(scope)
            if len(calls) > 1:
                raise o.Refused('synthetic hook recheck refusal')
            with original(session, scope) as fd:
                yield fd
        with patch.object(o.Session, 'open_scope_parent', fail_recheck):
            with self.assertRaisesRegex(ValueError, 'hook recheck refusal'):
                self.run_owner()
        self.assertEqual(calls, [self.scope, self.scope])
        self.assertFalse(self.destination.exists()); self.assertFalse(self.mutations)

    def test_scope_parent_hook_exit_refusal_closes_recheck_fd(self):
        self.prepare(); self.publish()
        original_parent, original_child = o.Session.open_scope_parent, p.child_open
        calls, recheck_fds = [], []
        @contextlib.contextmanager
        def fail_exit(session, scope):
            calls.append(scope)
            with original_parent(session, scope) as fd:
                yield fd
            if len(calls) == 2:
                raise o.Refused('synthetic hook exit refusal')
        def child(parent, name, flags):
            fd = original_child(parent, name, flags)
            if len(calls) == 2 and name == self.scope.name:
                recheck_fds.append(fd)
            return fd
        with patch.object(o.Session, 'open_scope_parent', fail_exit), \
                patch.object(p, 'child_open', side_effect=child):
            with self.assertRaisesRegex(ValueError, 'hook exit refusal'):
                self.run_owner()
        self.assertTrue(recheck_fds)
        for fd in set(recheck_fds):
            with self.assertRaises(OSError):
                self.raw_fstat(fd)
        self.assertFalse(self.destination.exists()); self.assertFalse(self.mutations)

    def test_mapped_id_hook_refusal_never_uses_marker_ids(self):
        self.prepare(); self.publish()
        with patch.object(o.Session, 'projection_execute_ids', side_effect=o.Refused('synthetic ID hook refusal')) as hook:
            with self.assertRaisesRegex(ValueError, 'ID hook refusal'):
                self.run_owner()
        hook.assert_called_once_with(self.marker)
        self.assertFalse(self.destination.exists()); self.assertFalse(self.mutations)

    def test_real_hooks_observe_exact_scope_marker_and_multiple_rechecks(self):
        self.prepare(); self.publish()
        original_parent, original_ids = o.Session.open_scope_parent, o.Session.projection_execute_ids
        scopes, markers = [], []
        @contextlib.contextmanager
        def parent(session, scope):
            scopes.append(scope)
            with original_parent(session, scope) as fd:
                yield fd
        def ids(session, marker):
            markers.append(marker)
            return original_ids(session, marker)
        with patch.object(o.Session, 'open_scope_parent', parent), \
                patch.object(o.Session, 'projection_execute_ids', ids):
            self.run_owner()
        self.assertGreater(len(scopes), 3)
        self.assertEqual(set(scopes), {self.scope})
        self.assertEqual(markers, [self.marker])

    def test_root_return_retains_per_domain_custody_and_post_handoff_inodes(self):
        self.prepare(); self.publish()
        proof = self.run_owner()
        custody = proof['projectionCustody']
        self.assertEqual(custody['selection']['domain'], self.domain)
        self.assertEqual(o.p.sha(o.p.encoded(custody)), proof['custodySha256'])
        pins = proof['runtimeCustody']
        self.assertIn('', pins)
        self.assertIn('projection.json', pins)
        for name, record in pins.items():
            self.assertEqual(record['uid'], self.row['uid'])
            self.assertEqual(record['gid'], self.accounts[self.row['user']].pw_gid)
            self.assertEqual(record['identity'][:2], [record['dev'], record['ino']])
            self.assertFalse(record['acl'])
            self.assertFalse(record['defaultAcl'])

    def test_actual_root_volumes_parent_defaults_preserved_through_real_owner(self):
        node = self.scope / 'volumes'
        node.chmod(0o755); self.set_owner(node, 0, 1000)
        self.acls[self.key(node)] = (
            acl([(2, 7, 1000), *[(2, 1, row['uid']) for row in self.rows]], group=7, mask=5, other=5),
            acl([(2, 7, 1000)], group=7, mask=7))
        before = self.acls[self.key(node)]
        self.prepare(); self.publish(); self.run_owner()
        self.assertEqual((node.stat().st_uid, node.stat().st_gid, stat.S_IMODE(node.stat().st_mode)), (0, 1000, 0o755))
        self.assertEqual(self.acls[self.key(node)], before)
        self.assertNotIn(node, [path for path, _, _ in self.mutations])

    def test_root_public_parent_foreign_default_writer_refused(self):
        node = self.scope / 'volumes'
        node.chmod(0o755); self.set_owner(node, 0, 1000)
        self.acls[self.key(node)] = acl([(2, 7, 1000)], mask=5, other=5), acl([(2, 7, 1001)])
        with self.assertRaises(ValueError):
            self.prepare()

    def test_root_public_parent_group_write_refused(self):
        node = self.scope / 'volumes'
        node.chmod(0o775); self.set_owner(node, 0, 1000)
        self.acls[self.key(node)] = acl([(2, 7, 1000)], other=5), b''
        with self.assertRaises(ValueError):
            self.prepare()

    def test_empty_domain_absent_runtime_source_and_identity_still_enforced(self):
        self.empty_domain()
        (self.release / 'runtime').rename(self.release / 'unread-secret-source')
        self.prepare(); self.publish()
        proof = self.run_owner()
        self.assertEqual(proof['services'], [])
        self.assertEqual(proof['configMounts'], [])
        self.assertEqual(proof['environmentInputs'], [])
        self.assertEqual(self.slot.stat().st_uid, self.row['uid'])
        self.assertTrue((self.release / 'unread-secret-source/stack.env').is_file())

    def test_empty_domain_service_mismatch_still_refused(self):
        self.empty_domain(); self.row['services'] = ['runner80']; self.reseal()
        with self.assertRaisesRegex(ValueError, 'service ownership'):
            self.prepare()
        self.assertFalse(self.destination.exists()); self.assertFalse(self.mutations)

    def test_dns_none_model_no_resolver_or_network_call(self):
        self.ir['services']['runner80']['dns'] = []
        self.ir['services']['runner80']['networkMode'] = 'none'
        self.reseal(); self.prepare(); self.publish(); proof = self.run_owner()
        self.assertEqual(proof['services'], ['runner80', 'test-runner'])


class External(Owner):
    external = True
    def test_no_adapter_still_refuses_external_ancestry(self):
        self.prepare(); self.publish()
        with self.assertRaises(ValueError):
            p.project(self.release, self.destination, self.domain, self.row['user'], self.row['uid'],
                      self.state, p.sha(p.encoded(self.new)), p.sha(p.encoded(self.marker)))
        self.assertFalse(self.destination.exists()); self.assertFalse(self.mutations)

    def test_external_metadata_unchanged_through_real_hook_handoff(self):
        parents = [self.external_parent.parent, self.external_parent]
        self.external_parent.parent.chmod(0o755)
        before = {node: (self.key(node), node.stat().st_uid, node.stat().st_gid,
                        node.stat().st_mode, self.acls.get(self.key(node), (b'', b''))) for node in parents}
        self.prepare(); self.publish(); self.run_owner()
        after = {node: (self.key(node), node.stat().st_uid, node.stat().st_gid,
                       node.stat().st_mode, self.acls.get(self.key(node), (b'', b''))) for node in parents}
        self.assertEqual(before, after)
        self.assertNotIn(self.external_parent, [path for path, _, _ in self.mutations])

    def test_mapped_namespace_root_execute_acl_real_hook(self):
        for node in (self.scope, self.scope / 'graph'):
            self.acls[self.key(node)] = (acl([(2, 1, self.row['uid']),
                                            (2, 1, o.storage.namespace_root_id(self.row['user']))]), b'')
        self.prepare(); self.publish(); self.run_owner()

    def test_foreign_external_acl_is_not_accepted_merely_because_pinned(self):
        self.acls[self.key(self.external_parent)] = acl([(2, 7, 1001)], other=5), acl(other=5)
        with self.assertRaisesRegex(ValueError, 'ACL'): self.prepare()

    def test_external_mode_groupwrite_not_generalized(self):
        self.external_parent.chmod(0o2777)
        with self.assertRaises(ValueError): self.prepare()

    def test_external_default_acl_race(self):
        key = self.key(self.external_parent)
        self.race(lambda: self.acls.__setitem__(key, (self.acls[key][0], b'')))

    def test_external_mount_identity_race(self):
        self.race(lambda: setattr(p.mount_id, 'return_value', 92))


class CanonicalLease(unittest.TestCase):
    def test_lock_fd9_observed_without_flock_acquisition(self):
        info = SimpleNamespace(st_dev=os.makedev(8, 1), st_ino=123, st_uid=0, st_gid=0,
                               st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_size=0, st_mtime_ns=0, st_ctime_ns=0)
        @contextlib.contextmanager
        def directory(*unused): yield 31
        with patch.object(o, 'root_chain'), patch.object(p, 'directory', side_effect=directory), \
                patch.object(p, 'child_open', return_value=32), patch.object(os, 'fstat', return_value=info), \
                patch.object(os, 'close'), patch('builtins.open', return_value=io.StringIO('lock:\t1: FLOCK ADVISORY WRITE 42 08:01:123 0 EOF\n')):
            o.lock_held(Path('/fixture'))

    def test_unlocked_fd9_is_not_acquired(self):
        info = SimpleNamespace(st_dev=1, st_ino=123, st_uid=0, st_gid=0,
                               st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_size=0, st_mtime_ns=0, st_ctime_ns=0)
        @contextlib.contextmanager
        def directory(*unused): yield 31
        with patch.object(o, 'root_chain'), patch.object(p, 'directory', side_effect=directory), \
                patch.object(p, 'child_open', return_value=32), patch.object(os, 'fstat', return_value=info), \
                patch.object(os, 'close'), patch('builtins.open', return_value=io.StringIO('pos:\t0\n')):
            with self.assertRaisesRegex(ValueError, 'exclusive'):
                o.lock_held(Path('/fixture'))

    def test_inactive_gate_delegates_only_to_canonical_read_only_owner(self):
        row = {'name': 'tests'}
        with patch.object(o.journal, 'selected_quarantine_plans', return_value=[('rootless-tests', ['canonical'], [])]), \
                patch.object(o.journal, 'offline_actor', return_value=row), \
                patch.object(o.journal, 'verify_offline_actor') as verify:
            self.assertIsNone(o.inactive(Path('/fixture'), 'tests'))
            verify.assert_called_once_with(row, ['canonical'])

    def test_running_manager_is_never_revived_stopped_or_admitted(self):
        with patch.object(o.journal, 'selected_quarantine_plans', return_value=[('rootless-tests', ['canonical'], [])]), \
                patch.object(o.journal, 'offline_actor', return_value=None), \
                patch.object(o.journal, 'verify_offline_actor') as verify:
            with self.assertRaisesRegex(ValueError, 'already stopped'):
                o.inactive(Path('/fixture'), 'tests')
            verify.assert_not_called()


if __name__ == '__main__':
    unittest.main()
