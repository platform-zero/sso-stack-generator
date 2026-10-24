#!/usr/bin/env python3
"""Isolated metadata sealing: real temp FDs/openat2/flock, model identities/ACLs.

Never chown, inspect host accounts/services, install, or touch the native scope.
Production profile/provenance/source selection and canonical FD9 observer run.
"""
import errno
import fcntl
import importlib.util
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).absolute().parents[1] / 'runtime-generator/podman-ops/native-metadata-owner.py'
spec = importlib.util.spec_from_file_location('tested_metadata_owner', SOURCE)
m = importlib.util.module_from_spec(spec)
exec(compile(SOURCE.read_bytes(), str(SOURCE), 'exec'), m.__dict__)
p, o = m.p, m.o


def acl(other=0):
    rows = [(1, 7, 0xffffffff), (2, 7, 1000), (4, 7, 0xffffffff), (16, 7, 0xffffffff), (32, other, 0xffffffff)]
    return struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *row) for row in rows)


class Metadata(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='metadata-sealing-model-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'metadata'
        self.bundle = self.base / 'candidate'
        self.old = self.root / 'releases/retired'
        self.external = self.base / 'mnt/stack'
        self.scope = self.external / 'synthetic'
        self.virtual, self.acls, self.changed = {}, {}, []
        self.raw_stat, self.raw_lstat, self.raw_fstat = os.stat, os.lstat, os.fstat
        self.raw_fchmod = os.fchmod
        for path in (self.old, self.bundle, self.scope):
            path.mkdir(parents=True, mode=0o700)
        # All fixture authority directories are private, except the exact root
        # being sealed and the source-declared external operator ancestry.
        for path in [self.base, *[p for p in self.base.rglob('*') if p.is_dir()]]:
            path.chmod(0o700)
        self.root.chmod(0o755)
        self.external.chmod(0o2775); self.scope.chmod(0o2770)
        self.operator = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name='operator')
        for path in (self.external, self.scope): self.set_owner(path, 1000, 1000)
        self.acls[self.key(self.external)] = acl(other=5), acl()
        self.acls[self.key(self.scope)] = acl(), acl()
        self.rows = [dict(name=name, uid=uid, user=user, subuidStart=2883584 + index * 65536,
            stateRoot=str(self.scope / 'state' / name), graphRoot=str(self.scope / 'graphs' / name),
            volumeRoot=str(self.scope / 'volumes' / name), services=[], persistentServices=[])
            for index, (name, (uid, user)) in enumerate(m.native.IDENTITIES.items())]
        self.scope_config = dict(root=str(self.scope), dataClass='synthetic')
        self.populate(self.bundle)
        self.populate(self.old, retired=True)
        self.intent = dict(schemaVersion=1, release=str(self.old), phase='retired-failed',
            previousRelease=None, steps=['preparing', 'failed', 'retired-failed'],
            dataPreserved=True, inputs=m.journal.fingerprint(self.old))
        self.write_records()
        marker_rows = [{key: row[key] for key in ('name', 'user', 'uid', *m.ROOT_KEYS)} for row in self.rows]
        self.marker = dict(schemaVersion=1, kind='standalone-stack-storage', site='test.invalid', scope=self.scope_config,
            domains=sorted(marker_rows, key=lambda row: row['name']),
            roots=sorted(row[key] for row in marker_rows for key in m.ROOT_KEYS))
        self.put(self.scope / m.storage.MARKER, p.encoded(self.marker))
        self.put(self.root / '.install.lock', b'')
        self.saved9 = None
        try: self.saved9 = os.dup(9)
        except OSError as error:
            if error.errno != errno.EBADF: raise
        self.lock = os.open(self.root / '.install.lock', os.O_RDONLY)
        if self.lock != 9: os.dup2(self.lock, 9)
        fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.addCleanup(self.close_lock)
        ancestor_keys = {self.key(path) for path in self.base.parents}
        test = self
        class VirtualStat:
            def __init__(inner, actual):
                inner.actual = actual
                key = actual.st_dev, actual.st_ino
                inner.st_uid, inner.st_gid = test.virtual.get(key, (0, 0))
                inner.st_mode = stat.S_IFDIR | 0o755 if key in ancestor_keys else actual.st_mode
            def __getattr__(inner, key): return getattr(inner.actual, key)
        def getacl(fd, name):
            info = self.raw_fstat(fd)
            values = self.acls.get((info.st_dev, info.st_ino), (b'', b''))
            return values[0 if name == 'system.posix_acl_access' else 1]
        def chmod(fd, mode):
            self.assertEqual(self.key(self.root), (self.raw_fstat(fd).st_dev, self.raw_fstat(fd).st_ino))
            self.assertEqual(mode, 0o700)
            self.changed.append((self.key(self.root), mode))
            self.raw_fchmod(fd, mode)
        real_fullmatch = m.v.re.fullmatch
        def fullmatch(pattern, value, *args, **kwargs):
            # ONLY the canonical /var/lib metadata-root location grammar gets a
            # fixture mapping. All other profile/selection validators are real.
            if pattern == r'/var/lib/(?:webservices|stack-[a-z0-9-]{1,48})' and value == str(self.root):
                return real_fullmatch(r'.+', value)
            return real_fullmatch(pattern, value, *args, **kwargs)
        items = [patch.object(os, 'stat', side_effect=lambda *a, **kw: VirtualStat(self.raw_stat(*a, **kw))),
            patch.object(os, 'lstat', side_effect=lambda *a, **kw: VirtualStat(self.raw_lstat(*a, **kw))),
            patch.object(os, 'fstat', side_effect=lambda fd: VirtualStat(self.raw_fstat(fd))),
            patch.object(os, 'geteuid', return_value=0), patch.object(os, 'fchmod', side_effect=chmod),
            patch.object(p, 'acl_bytes', side_effect=getacl), patch.object(o, 'EXTERNAL_OPERATOR', self.external),
            patch.object(o.pwd, 'getpwuid', return_value=self.operator),
            patch.object(o.pwd, 'getpwall', return_value=[self.operator]),
            patch.object(o.grp, 'getgrgid', return_value=SimpleNamespace(gr_mem=[])),
            patch.object(m.v.re, 'fullmatch', side_effect=fullmatch),
            patch.object(os, 'chown', side_effect=AssertionError('no chown')),
            patch.object(os, 'fchown', side_effect=AssertionError('no fchown')),
            patch.object(os, 'mkdir', side_effect=AssertionError('no new directories')),
            patch.object(subprocess, 'run', side_effect=AssertionError('no host queries')),
            patch.object(subprocess, 'Popen', side_effect=AssertionError('no processes')),
            patch.object(subprocess, 'check_output', side_effect=AssertionError('no host queries'))]
        for item in items: item.start()
        self.addCleanup(patch.stopall)

    def close_lock(self):
        if self.saved9 is not None:
            os.dup2(self.saved9, 9); os.close(self.saved9)
        else:
            try: os.close(9)
            except OSError: pass
        if self.lock != 9: os.close(self.lock)

    def key(self, path):
        info = self.raw_lstat(path)
        return info.st_dev, info.st_ino

    def set_owner(self, path, uid, gid): self.virtual[self.key(path)] = uid, gid

    def put(self, path, body):
        if not path.parent.exists(): path.parent.mkdir(parents=True, mode=0o700)
        path.write_bytes(body); path.chmod(0o600)

    def populate(self, bundle, retired=False):
        ir = dict(schemaVersion=1, services={'edge': dict(placement='rootful', lifecycle='daemon', target='core',
                  image='sha256:' + 'a' * 64)}, volumes={}, networks={})
        if retired:
            # Previously declared unmarked on-demand Huly remains stop/source
            # custody only, not a newly managed/activatable candidate service.
            ir['services']['huly-identity-bootstrap'] = dict(placement='rootless', rootlessDomain='apps',
                lifecycle='on-demand', image='sha256:' + 'b' * 64,
                build={}, frozenBuildImage='sha256:' + 'b' * 64)
        rows = [dict(row, services=(['huly-identity-bootstrap'] if retired and row['name'] == 'apps' else []))
                for row in self.rows]
        metadata = dict(schemaVersion=1, deploymentMode='standalone', installerStateRoot=str(self.root),
                        storageScope=self.scope_config, domains=rows)
        manifest = dict(site='test.invalid', deploymentMode='standalone', installerStateRoot=str(self.root), storageScope=self.scope_config)
        for name, value in [('stack.ir.json', ir), ('podman-domains.json', metadata), ('site/manifest.json', manifest)]:
            self.put(bundle / name, p.encoded(value))
        provenance = dict(manifestSha256=p.sha(p.encoded(manifest)))
        self.put(bundle / 'source-provenance.json', p.encoded(provenance))
        self.put(bundle / 'bundle.json', p.encoded(dict(backend='podman', deploymentMode='standalone',
            sourceProvenanceSha256=p.sha(p.encoded(provenance)), irSha256=p.sha(p.encoded(ir)))))
        for scope in ['rootful', *['rootless-' + name for name in m.native.IDENTITIES]]:
            for target in ('core', 'apps', 'observability'):
                units = 'webservices-edge.service' if scope == 'rootful' and target == 'core' else ''
                self.put(bundle / 'quadlet' / scope / ('webservices-' + target + '.target'),
                    ('[Unit]\nPartOf=webservices.target\nWants=' + units + '\n[Install]\nWantedBy=webservices.target\n').encode())
            self.put(bundle / 'quadlet' / scope / 'webservices.target',
                ('[Unit]\nWants=webservices-core.target webservices-apps.target webservices-observability.target\n[Install]\nWantedBy='
                 + ('multi-user.target' if scope == 'rootful' else 'default.target') + '\n').encode())
        self.put(bundle / 'quadlet/rootful/webservices-edge.container',
            ('[Unit]\nPartOf=webservices-core.target\n[Container]\nContainerName=edge\nImage=sha256:' + 'a' * 64
             + '\n[Service]\n[Install]\nWantedBy=webservices-core.target\n').encode())
        for directory in bundle.rglob('*'):
            if directory.is_dir(): directory.chmod(0o700)

    def write_records(self):
        self.put(self.root / '.install-intent.json', p.encoded(self.intent))
        self.put(self.old / 'installation-receipt.json', p.encoded(self.intent))

    def reseal_profile(self, path):
        manifest = p.strict((path / 'site/manifest.json').read_bytes())
        ir = (path / 'stack.ir.json').read_bytes()
        provenance = p.encoded(dict(manifestSha256=p.sha(p.encoded(manifest))))
        self.put(path / 'source-provenance.json', provenance)
        build = p.strict((path / 'bundle.json').read_bytes())
        build.update(sourceProvenanceSha256=p.sha(provenance), irSha256=p.sha(ir))
        self.put(path / 'bundle.json', p.encoded(build))

    def mutate_json(self, path, change):
        value = p.strict(path.read_bytes()); change(value); self.put(path, p.encoded(value))

    def seal(self): return m.seal(self.root, self.bundle)

    def owner(self):
        owner = m.Sealing(self.root, self.bundle)
        self.addCleanup(owner.close)
        return owner

    def test_exact0755_transition_preserves_sources_receipts_scope_and_evidence(self):
        evidence = self.root / 'authored-evidence'; self.put(evidence, b'preserve')
        before = {path: path.read_bytes() for path in self.base.rglob('*') if path.is_file()}
        proof = self.seal()
        self.assertTrue(proof['changed']); self.assertEqual(proof['before']['mode'], 0o755)
        self.assertEqual(proof['after']['mode'], 0o700); self.assertEqual(len(self.changed), 1)
        self.assertFalse(proof['activationAuthorized']); self.assertFalse(proof['readinessAuthorized'])
        self.assertFalse(proof['resetAuthorized']); self.assertEqual(proof['phase'], 'retired-failed')
        self.assertEqual({path: path.read_bytes() for path in before}, before)
        self.assertFalse(any((self.scope / name).exists() for name in ('state', 'graphs', 'volumes')))

    def test_idempotent0700_repeats_all_proofs_without_chmod(self):
        self.root.chmod(0o700)
        proof = self.seal()
        self.assertFalse(proof['changed']); self.assertEqual(self.changed, [])

    def test_second_call_idempotent(self):
        self.seal(); proof = self.seal()
        self.assertFalse(proof['changed']); self.assertEqual(len(self.changed), 1)

    def test_real_current_selected_release_preserved(self):
        (self.root / 'current').symlink_to('releases/retired')
        proof = self.seal()
        self.assertEqual(proof['current']['current']['target'], 'releases/retired')
        self.assertEqual(os.readlink(self.root / 'current'), 'releases/retired')

    def test_old_runtime_config_data_are_not_read_or_walked(self):
        for name in ('runtime', 'config', 'appdata'):
            # A final symlink would fail a source walk; no selected-source read
            # may even traverse these old release entries.
            (self.old / name).symlink_to(self.base / 'missing-private-data')
        self.assertTrue(self.seal()['changed'])

    def set_native_marker_acl(self, user=1000, mask=0):
        marker = self.scope / m.storage.MARKER
        self.set_owner(marker, 0, 1000)
        rows = [(1, 6, 0xffffffff), (2, 7, user), (4, 7, 0xffffffff),
                (16, mask, 0xffffffff), (32, 0, 0xffffffff)]
        value = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *row) for row in rows)
        self.acls[self.key(marker)] = value, b''
        return marker, value

    def test_native0600_scope_marker_keeps_gid_and_masked_operator_acl(self):
        marker, value = self.set_native_marker_acl()
        body = marker.read_bytes()
        self.assertTrue(self.seal()['changed'])
        self.assertEqual(marker.read_bytes(), body)
        self.assertEqual(self.acls[self.key(marker)], (value, b''))
        self.assertEqual(self.virtual[self.key(marker)], (0, 1000))

    def test_unknown_latent_scope_marker_acl_is_not_native(self):
        self.set_native_marker_acl(user=1001)
        with self.assertRaises(ValueError): self.seal()
        self.assertFalse(self.changed)

    def test_nonzero_scope_marker_acl_mask_refuses_without_repair(self):
        marker, value = self.set_native_marker_acl(mask=1)
        with self.assertRaises(ValueError): self.seal()
        self.assertFalse(self.changed)
        self.assertEqual(self.acls[self.key(marker)], (value, b''))

    def test_legacy_absent_ranges_remain_unknown_not_candidate_adopted(self):
        self.mutate_json(self.old / 'podman-domains.json',
                         lambda metadata: [row.pop('subuidStart') for row in metadata['domains']])
        self.intent['inputs'] = m.journal.fingerprint(self.old); self.write_records()
        proof = self.seal()
        self.assertTrue(proof['changed'])
        self.assertEqual(proof['historicalNamespaceStarts'], {row['name']: None for row in self.rows})
        self.assertFalse(proof['resetAuthorized'])
        self.assertFalse(proof['activationAuthorized'])

    def test_legacy_explicit_null_range_is_not_absence(self):
        self.mutate_json(self.old / 'podman-domains.json',
                         lambda metadata: metadata['domains'][0].update(subuidStart=None))
        self.intent['inputs'] = m.journal.fingerprint(self.old); self.write_records()
        with self.assertRaises(ValueError): self.seal()
        self.assertFalse(self.changed)

    def test_new_candidate_must_declare_namespace_ranges(self):
        self.mutate_json(self.bundle / 'podman-domains.json',
                         lambda metadata: [row.pop('subuidStart') for row in metadata['domains']])
        with self.assertRaises(ValueError): self.seal()
        self.assertFalse(self.changed)

    def test_retired_legacy_named_volume_is_source_not_new_activation(self):
        self.mutate_json(self.old / 'stack.ir.json', lambda ir: (
            ir['volumes'].update({'legacy-huly': {'driver': 'local'}}),
            ir['services']['edge'].update(volumes=['legacy-huly:/data'])))
        self.reseal_profile(self.old)
        self.intent['inputs'] = m.journal.fingerprint(self.old); self.write_records()
        with self.assertRaisesRegex(ValueError, 'Standalone named volume lacks hostPath'):
            m.v.verify(self.old)
        self.assertTrue(self.seal()['changed'])
        self.assertEqual(self.intent['phase'], 'retired-failed')

    def test_candidate_mount_failure_never_becomes_activation_authority(self):
        self.mutate_json(self.bundle / 'stack.ir.json', lambda ir: (
            ir['volumes'].update({'unclaimed': {'driver': 'local'}}),
            ir['services']['edge'].update(volumes=['unclaimed:/data'])))
        self.reseal_profile(self.bundle)
        with self.assertRaisesRegex(ValueError, 'Standalone named volume lacks hostPath'):
            m.v.verify(self.bundle)
        proof = self.seal()
        self.assertTrue(proof['changed'])
        self.assertFalse(proof['activationAuthorized'])
        self.assertFalse(proof['readinessAuthorized'])
        self.assertFalse(proof['resetAuthorized'])
        # Sealing metadata NEVER changes the application's failed admission.
        with self.assertRaisesRegex(ValueError, 'Standalone named volume lacks hostPath'):
            m.v.verify(self.bundle)

    def test_retired_unmarked_huly_is_not_candidate_activation(self):
        with self.assertRaises(ValueError): m.native.source_plan(self.old)
        self.assertTrue(self.seal()['changed'])

    def test_missing_fd9_refused(self):
        os.close(9)
        with self.assertRaises((OSError, ValueError)): self.seal()
        self.assertEqual(self.changed, [])

    def test_unlocked_fd9_refused(self):
        fcntl.flock(9, fcntl.LOCK_UN)
        with self.assertRaisesRegex(ValueError, 'lease'): self.seal()
        self.assertEqual(self.changed, [])

    def test_wrong_fd9_refused(self):
        other = self.root / 'wrong-lock'; self.put(other, b'')
        fd = os.open(other, os.O_RDONLY)
        try:
            os.dup2(fd, 9)
            with self.assertRaisesRegex(ValueError, 'FD9'): self.seal()
        finally: os.close(fd)
        self.assertEqual(self.changed, [])

    def test_missing_lock_is_not_created(self):
        (self.root / '.install.lock').unlink()
        with self.assertRaises((ValueError, OSError)): self.seal()
        self.assertFalse((self.root / '.install.lock').exists()); self.assertEqual(self.changed, [])

    def test_nonempty_lock_refused(self):
        self.put(self.root / '.install.lock', b'foreign')
        with self.assertRaisesRegex(ValueError, 'empty'): self.seal()

    def test_metadata_wrong_owner_refused(self):
        self.set_owner(self.root, 1000, 1000)
        with self.assertRaises(ValueError): self.seal()
        self.assertEqual(self.changed, [])

    def test_metadata_wrong_group_refused(self):
        self.set_owner(self.root, 0, 1000)
        with self.assertRaises(ValueError): self.seal()

    def test_metadata0750_refused(self):
        self.root.chmod(0o750)
        with self.assertRaisesRegex(ValueError, 'exactly'): self.seal()

    def test_metadata_special_bits_refused(self):
        self.root.chmod(0o2755)
        with self.assertRaises(ValueError): self.seal()

    def test_metadata_writable_refused(self):
        self.root.chmod(0o775)
        with self.assertRaises(ValueError): self.seal()

    def test_metadata_access_acl_refused(self):
        self.acls[self.key(self.root)] = acl(), b''
        with self.assertRaisesRegex(ValueError, 'ACL'): self.seal()

    def test_metadata_default_acl_refused(self):
        self.acls[self.key(self.root)] = b'', acl()
        with self.assertRaisesRegex(ValueError, 'ACL'): self.seal()

    def test_metadata0700_still_requires_all_proofs(self):
        self.root.chmod(0o700); (self.root / '.install-intent.json').unlink()
        with self.assertRaises((ValueError, OSError)): self.seal()
        self.assertEqual(self.changed, [])

    def test_metadata_symlink_refused(self):
        alias = self.base / 'linked'; alias.symlink_to(self.root)
        with self.assertRaises((ValueError, OSError)): m.seal(alias, self.bundle)

    def test_ancestor_foreign_writer_refused(self):
        self.base.chmod(0o770)
        with self.assertRaises(ValueError): self.seal()

    def test_operator_candidate_not_accepted(self):
        self.set_owner(self.bundle, 1000, 1000)
        with self.assertRaises(ValueError): self.seal()

    def test_candidate_nested_operator_file_refused(self):
        path = self.bundle / 'source.txt'; self.put(path, b'public')
        self.set_owner(path, 1000, 1000)
        with self.assertRaises(ValueError): self.seal()

    def test_candidate_source_hardlink_refused(self):
        os.link(self.bundle / 'bundle.json', self.bundle / 'alias')
        with self.assertRaises(ValueError): self.seal()

    def test_candidate_symlink_refused(self):
        (self.bundle / 'alias').symlink_to(self.bundle / 'bundle.json')
        with self.assertRaises(ValueError): self.seal()

    def test_candidate_default_acl_refused(self):
        self.acls[self.key(self.bundle)] = b'', acl()
        with self.assertRaises(ValueError): self.seal()

    def test_source_provenance_mismatch_refused(self):
        self.put(self.bundle / 'source-provenance.json', b'{}\n')
        with self.assertRaisesRegex(ValueError, 'provenance'): self.seal()

    def test_different_candidate_root_refused(self):
        self.mutate_json(self.bundle / 'podman-domains.json', lambda value: value.update(installerStateRoot='/var/lib/stack-other'))
        with self.assertRaisesRegex(ValueError, 'binding'): self.seal()

    def test_different_candidate_site_refused(self):
        self.mutate_json(self.bundle / 'site/manifest.json', lambda value: value.update(site='different.invalid'))
        self.reseal_profile(self.bundle)
        with self.assertRaisesRegex(ValueError, 'allocation differs'): self.seal()

    def test_candidate_production_refused(self):
        self.mutate_json(self.bundle / 'site/manifest.json', lambda value: value['storageScope'].update(dataClass='production'))
        with self.assertRaisesRegex(ValueError, 'synthetic'): self.seal()

    def test_different_allocation_refused(self):
        self.mutate_json(self.bundle / 'podman-domains.json', lambda value: value['domains'][0].update(subuidStart=9000000))
        with self.assertRaisesRegex(ValueError, 'allocation differs'): self.seal()

    def test_overlapping_allocation_refused(self):
        self.mutate_json(self.bundle / 'podman-domains.json', lambda value: value['domains'][0].update(subuidStart=value['domains'][1]['subuidStart']))
        with self.assertRaisesRegex(ValueError, 'overlapping'): self.seal()

    def test_receipt_intent_mismatch_refused(self):
        self.put(self.old / 'installation-receipt.json', p.encoded(dict(self.intent, dataPreserved=False)))
        with self.assertRaisesRegex(ValueError, 'bytes differ'): self.seal()

    def test_old_source_hash_mismatch_refused(self):
        self.put(self.old / 'stack.ir.json', b'{}\n')
        with self.assertRaisesRegex(ValueError, 'fingerprint'): self.seal()

    def test_old_release0755_refused(self):
        self.old.chmod(0o755)
        with self.assertRaises(ValueError): self.seal()

    def test_private_intent_required(self):
        (self.root / '.install-intent.json').chmod(0o644)
        with self.assertRaises(ValueError): self.seal()

    def test_private_receipt_required(self):
        (self.old / 'installation-receipt.json').chmod(0o644)
        with self.assertRaises(ValueError): self.seal()

    def test_intent_hardlink_refused(self):
        os.link(self.root / '.install-intent.json', self.root / 'alias')
        with self.assertRaises(ValueError): self.seal()

    def test_marker_mismatch_refused(self):
        self.put(self.scope / m.storage.MARKER, b'{}\n')
        with self.assertRaisesRegex(ValueError, 'marker'): self.seal()

    def test_marker_missing_no_adoption(self):
        (self.scope / m.storage.MARKER).unlink()
        with self.assertRaises((ValueError, OSError)): self.seal()

    def test_foreign_current_refused(self):
        (self.root / 'current').symlink_to('/foreign/release')
        with self.assertRaisesRegex(ValueError, 'pointer'): self.seal()

    def test_current_regular_file_refused(self):
        self.put(self.root / 'current', b'foreign')
        with self.assertRaisesRegex(ValueError, 'pointer'): self.seal()

    def test_source_cas_after_preflight(self):
        owner = self.owner()
        path = self.bundle / 'quadlet/rootful/webservices-edge.container'
        self.put(path, path.read_bytes() + b'#changed\n')
        with self.assertRaisesRegex(ValueError, 'CAS'): owner.run()
        self.assertEqual(self.changed, [])

    def test_marker_cas_after_preflight(self):
        owner = self.owner()
        self.put(self.scope / m.storage.MARKER, p.encoded(dict(self.marker, site='changed.invalid')))
        with self.assertRaisesRegex(ValueError, 'CAS'): owner.run()
        self.assertEqual(self.changed, [])

    def test_current_cas_after_preflight(self):
        (self.root / 'current').symlink_to(self.old)
        owner = self.owner()
        (self.root / 'current').unlink(); (self.root / 'current').symlink_to(self.old)
        with self.assertRaisesRegex(ValueError, 'CAS'): owner.run()
        self.assertEqual(self.changed, [])

    def test_mount_cas_after_preflight(self):
        owner = self.owner(); real = p.mount_id
        with patch.object(p, 'mount_id', side_effect=lambda fd: real(fd) + 1):
            with self.assertRaisesRegex(ValueError, 'CAS'): owner.run()
        self.assertEqual(self.changed, [])

    def test_intent_aba_same_bytes_refused(self):
        owner = self.owner()
        path = self.root / '.install-intent.json'; body = path.read_bytes()
        path.unlink(); self.put(path, body)
        with self.assertRaisesRegex(ValueError, 'CAS'): owner.run()
        self.assertEqual(self.changed, [])

    def test_lock_release_after_preflight_refused(self):
        owner = self.owner(); fcntl.flock(9, fcntl.LOCK_UN)
        with self.assertRaisesRegex(ValueError, 'lease'): owner.run()
        self.assertEqual(self.changed, [])

    def test_deadline_fail_closed(self):
        owner = self.owner(); owner.deadline = 0
        with self.assertRaisesRegex(ValueError, 'deadline'): owner.run()
        self.assertEqual(self.changed, [])

    def test_intent_inplace_same_bytes_cas_refused(self):
        owner = self.owner()
        path = self.root / '.install-intent.json'; self.put(path, path.read_bytes())
        with self.assertRaisesRegex(ValueError, 'CAS'): owner.run()
        self.assertEqual(self.changed, [])

    def test_old_release_path_replacement_refused(self):
        owner = self.owner()
        moved = self.old.with_name('moved')
        self.old.rename(moved); self.old.symlink_to(moved)
        with self.assertRaises((ValueError, OSError)): owner.run()
        self.assertEqual(self.changed, [])

    def test_metadata_root_path_replacement_refused(self):
        owner = self.owner()
        moved = self.root.with_name('moved')
        self.root.rename(moved); self.root.symlink_to(moved)
        with self.assertRaises((ValueError, OSError)): owner.run()
        self.assertEqual(self.changed, [])

    def test_selected_old_production_even_with_rehashed_receipt_refused(self):
        for name in ('site/manifest.json', 'podman-domains.json'):
            self.mutate_json(self.old / name, lambda value: value['storageScope'].update(dataClass='production'))
        self.reseal_profile(self.old)
        self.intent['inputs'] = m.journal.fingerprint(self.old); self.write_records()
        with self.assertRaisesRegex(ValueError, 'synthetic'): self.seal()
        self.assertEqual(self.changed, [])

    def test_unclaimed0755_refused(self):
        (self.root / '.install-intent.json').unlink()
        with self.assertRaises((ValueError, OSError)): self.seal()
        self.assertEqual(self.changed, [])

    def test_group_foreign_writer_refused(self):
        with patch.object(o.grp, 'getgrgid', return_value=SimpleNamespace(gr_mem=['foreign'])):
            with self.assertRaisesRegex(ValueError, 'foreign'): self.seal()
        self.assertEqual(self.changed, [])

    def test_source_acl_cas_refused(self):
        owner = self.owner()
        self.acls[self.key(self.bundle / 'bundle.json')] = acl(), b''
        with self.assertRaisesRegex(ValueError, 'ACL'): owner.run()
        self.assertEqual(self.changed, [])

    def test_nonobject_profile_refused(self):
        self.put(self.bundle / 'site/manifest.json', b'[]\n')
        with self.assertRaisesRegex(ValueError, 'objects'): self.seal()
        self.assertEqual(self.changed, [])

    def test_nonobject_storage_scope_refused(self):
        self.mutate_json(self.bundle / 'site/manifest.json', lambda value: value.update(storageScope=None))
        with self.assertRaisesRegex(ValueError, 'objects'): self.seal()
        self.assertEqual(self.changed, [])

    def test_nonroot_refused(self):
        with patch.object(os, 'geteuid', return_value=1000):
            with self.assertRaisesRegex(ValueError, 'root'): self.seal()
        self.assertEqual(self.changed, [])

    def test_after_chmod_mutation_no_proof(self):
        owner = self.owner()
        def mutate(fd, mode):
            self.raw_fchmod(fd, mode)
            self.put(self.old / 'installation-receipt.json', b'{}\n')
        with patch.object(os, 'fchmod', side_effect=mutate):
            with self.assertRaises(ValueError): owner.run()
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)


if __name__ == '__main__':
    unittest.main()
