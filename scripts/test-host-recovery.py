#!/usr/bin/env python3
"""Unprivileged temp-root contract proof; NOT installed/real-age acceptance.

No host manager/container/network calls. Root ownership is mapped to this test
user only inside mocks; native bundle/marker/quarantine authority is fixture
injected. Real native fingerprint logic, journal shape, archive parser, fd walks,
subprocess pipes, filesystem renames, CAS and failure handling are exercised.
"""
import hashlib
import importlib.util
import io
import json
import os
import struct
from pathlib import Path
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/host-recovery.py'
spec = importlib.util.spec_from_file_location('host_recovery_test', SOURCE)
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)

FAKE_AGE = '''#!/usr/bin/python3
# Fixture protocol only; deliberately NOT a claim about real age cryptography.
import hashlib, hmac, os, sys
args=sys.argv[1:]
body=sys.stdin.buffer.read()
if '--encrypt' in args:
    key=b'fixture-key'
    sys.stdout.buffer.write(b'MOCK-AGE\\n'+hmac.digest(key,body,'sha256')+body)
else:
    path=args[args.index('--identity')+1]
    with open(path,'rb') as f: key=f.read()
    if body[:9]!=b'MOCK-AGE\\n' or not hmac.compare_digest(body[9:41],hmac.digest(key,body[41:],'sha256')):
        # Emit untrusted plaintext before error, like a streaming decryptor may.
        sys.stdout.buffer.write(body[41:]); sys.exit(1)
    sys.stdout.buffer.write(body[41:])
'''


def put(path, data, mode=0o600):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else r.canonical(data))
    path.chmod(mode)


class Recovery(unittest.TestCase):
    def setUp(self):
        previous = os.umask(0o077); self.addCleanup(os.umask, previous)
        self.temp = tempfile.TemporaryDirectory(prefix='host-recovery-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'native'; self.root.mkdir(mode=0o700)
        self.release = self.root / 'releases/fixture'; self.release.mkdir(parents=True, mode=0o700)
        self.scope = self.base / 'synthetic'; self.scope.mkdir(mode=0o700)
        self.volumes = self.scope / 'volumes'; self.volumes.mkdir(mode=0o700)
        self.db = self.volumes / 'postgres'; self.db.mkdir(mode=0o700)
        self.blobs = self.volumes / 'blobs'; self.blobs.mkdir(mode=0o700)
        put(self.db / 'identity.db', b'synthetic alice identity')
        put(self.blobs / 'object.bin', b'synthetic blob payload')
        put(self.blobs / 'nested/document.txt', b'populated synthetic document')
        put(self.release / 'runtime/configs/application.json', {'synthetic': True})
        put(self.release / 'runtime/stack.env', b'SYNTHETIC=true\n')
        self.domains = [{'name': 'identity', 'user': 'fixture-identity', 'uid': 12345,
                         'stateRoot': str(self.scope / 'domains/identity/state'),
                         'graphRoot': str(self.scope / 'domains/identity/graph'),
                         'volumeRoot': str(self.scope / 'domains/identity/volumes')}]
        self.binding = {'schemaVersion': 1, 'kind': 'standalone-stack-storage', 'site': 'fixture',
                        'scope': {'root': str(self.scope), 'dataClass': 'synthetic'},
                        'domains': self.domains, 'roots': sorted(self.domains[0][k]
                            for k in ('stateRoot', 'graphRoot', 'volumeRoot'))}
        self.ir = {'services': {
            'keycloak': {'placement': 'rootful', 'volumes': ['./configs/application.json:/config:ro']},
            'postgres': {'placement': 'rootful', 'volumes': ['postgres:/var/lib/postgresql/data']},
            'content': {'placement': 'rootful', 'volumes': ['blobs:/objects']}},
            'volumes': {'postgres': {'hostPath': str(self.db)}, 'blobs': {'hostPath': str(self.blobs)}}}
        for name in r.journal.CORE_INPUTS + r.journal.PINNED_INPUTS:
            put(self.release / name, self.ir if name == 'stack.ir.json' else {'syntheticFixture': name})
        put(self.release / 'site/manifest.json', {'installerStateRoot': str(self.root)})
        put(self.scope / r.storage.MARKER, self.binding)
        self.native = {'schemaVersion': 1, 'phase': 'active', 'release': str(self.release),
                       'inputs': r.journal.fingerprint(self.release), 'steps': list(r.journal.PHASES[:5]),
                       'previousRelease': None}
        self.save_native()
        (self.root / 'current').symlink_to(self.release)
        self.archive_dir = self.base / 'archives'; self.archive_dir.mkdir(mode=0o700)
        self.key_dir = self.base / 'separate-key'; self.key_dir.mkdir(mode=0o700)
        self.key = self.key_dir / 'identity'; put(self.key, b'fixture-key')
        self.archive = self.archive_dir / 'snapshot.age'
        self.bin = self.base / 'bin'; self.bin.mkdir(mode=0o700)
        self.age = self.bin / 'age'; put(self.age, FAKE_AGE.encode(), 0o700)
        self.quiesced = True
        self.approvals = []
        self.native_storage_authority = r.storage.authority
        self.patches = [
            patch.object(r, 'OWNER', os.getuid()),
            patch.object(r, 'mount_points', return_value=set()),
            patch.object(r.os, 'geteuid', return_value=0),
            patch.object(r.journal, 'read', side_effect=lambda p: r.strict(r.read_file(p, private=True))),
            patch.object(r.storage, 'authority', side_effect=lambda release: (self.scope, None, self.binding)),
            patch.object(r.storage, 'marker', side_effect=self.check_marker),
            patch.object(r.journal, 'verify_quarantined', side_effect=self.check_quiescence),
        ]
        for mocking in self.patches:
            mocking.start(); self.addCleanup(mocking.stop)
        self.backend = r.Backend(self.root, hashlib.sha256((self.root / '.install-intent.json').read_bytes()).hexdigest(), self.age)
        self.operation_count = 0

    def save_native(self):
        put(self.root / '.install-intent.json', self.native)
        put(self.release / 'installation-receipt.json', self.native)

    def rebind_ir(self):
        put(self.release / 'stack.ir.json', self.ir)
        self.native['inputs'] = r.journal.fingerprint(self.release)
        self.save_native()
        self.backend.expected = r.file_sha(self.root / '.install-intent.json')

    def check_marker(self, scope, expected):
        if r.strict(r.read_file(scope / r.storage.MARKER, private=True)) != expected:
            raise ValueError('Synthetic ownership marker drift')

    def check_quiescence(self, release):
        self.assertEqual(release, self.release)
        if not self.quiesced: raise ValueError('Selected fixture is not stopped/quarantined')

    def approve(self, request):
        self.approvals.append(request)
        self.assertFalse(request['restart'])
        return request

    def op(self):
        self.operation_count += 1
        return format(self.operation_count, '032x')

    def backup(self):
        return self.backend.backup(self.archive, 'age1' + 'q' * 58, self.op(), self.approve)

    def restore(self, digest=None, key=None):
        return self.backend.restore(self.archive, digest or r.file_sha(self.archive), key or self.key, self.op(), self.approve)

    def originals(self):
        return ((self.db / 'identity.db').read_bytes(), (self.blobs / 'object.bin').read_bytes(),
                (self.release / 'runtime/stack.env').read_bytes())

    def changed(self):
        put(self.db / 'identity.db', b'new synthetic identity')
        put(self.blobs / 'object.bin', b'new synthetic blob')
        put(self.release / 'runtime/stack.env', b'NEW_SYNTHETIC=true\n')

    def repack(self, mutate=None, tar_extra=None):
        # Fixture tamper with fresh authenticated mock ciphertext. Exercises the
        # archive policy independently of ciphertext authentication checks.
        body = self.archive.read_bytes()[41:]
        with tarfile.open(fileobj=io.BytesIO(body), mode='r:') as tar:
            items = [(member, tar.extractfile(member).read() if member.isfile() else None) for member in tar]
        manifest = r.strict(items[0][1])
        if mutate: mutate(manifest, items)
        items[0] = (items[0][0], r.canonical(manifest)); items[0][0].size = len(items[0][1])
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as tar:
            for item, data in items:
                tar.addfile(item, io.BytesIO(data) if data is not None else None)
            if tar_extra: tar_extra(tar)
        import hmac
        body = output.getvalue()
        self.archive.write_bytes(b'MOCK-AGE\n' + hmac.digest(b'fixture-key', body, 'sha256') + body)

    def test_cold_encrypted_roundtrip_identity_blobs_config_and_retained_originals(self):
        original = self.originals()
        source_receipt = (self.root / '.install-intent.json').read_bytes()
        result = self.backup()
        self.assertTrue(result['encrypted']); self.assertFalse(result['installedAcceptance'])
        self.assertNotIn(original[0], self.archive.read_bytes()[:41])  # mock is not real encryption!
        self.assertEqual(self.archive.stat().st_mode & 0o777, 0o600)
        self.changed(); displaced = self.originals()
        result = self.restore()
        self.assertTrue(result['restored']); self.assertTrue(result['originalsRetained'])
        self.assertFalse(result['restart']); self.assertEqual(self.originals(), original)
        row = r.strict(r.read_file(self.backend.intent, private=True))
        self.assertEqual(row['phase'], 'committed')
        retained = {Path(s['root']).name: Path(s['area']) / 'original' for s in row['stages']}
        self.assertEqual((retained['postgres'] / 'identity.db').read_bytes(), displaced[0])
        self.assertEqual((retained['blobs'] / 'object.bin').read_bytes(), displaced[1])
        self.assertEqual((retained['runtime'] / 'stack.env').read_bytes(), displaced[2])
        self.assertEqual((self.root / '.install-intent.json').read_bytes(), source_receipt)
        self.assertEqual(self.key.read_bytes(), b'fixture-key')
        self.assertFalse(list(self.backend.state.rglob('authenticated.tar')))

    def test_running_stack_rejected_before_approval_or_crypto(self):
        self.quiesced = False
        with self.assertRaises(ValueError): self.backup()
        self.assertFalse(self.archive.exists()); self.assertEqual(self.approvals, [])

    def test_no_approval_no_payload_mutation(self):
        before = self.originals()
        with self.assertRaises(ValueError):
            self.backend.backup(self.archive, 'age1' + 'q' * 58, self.op(), lambda request: {})
        self.assertFalse(self.archive.exists()); self.assertEqual(self.originals(), before)

    def test_no_root_and_native_lock_exclusion(self):
        with patch.object(r.os, 'geteuid', return_value=1000):
            with self.assertRaises(ValueError): self.backend.plan()
        with self.backend.locked():
            with self.assertRaises(BlockingIOError): self.backend.plan()

    def test_receipt_pin_pointer_marker_and_cas_drift_refuse(self):
        for target in (self.root / '.install-intent.json', self.release / 'installation-receipt.json',
                       self.release / 'site/manifest.json', self.scope / r.storage.MARKER):
            old = target.read_bytes(); put(target, {'changed': True})
            with self.assertRaises((ValueError, KeyError)): self.backend.plan()
            target.write_bytes(old)
        pointer = self.root / 'current'; pointer.unlink(); pointer.symlink_to(self.base)
        with self.assertRaises(ValueError): self.backend.plan()
        self.assertEqual(self.approvals, [])

    def test_production_or_legacy_pin_set_refused(self):
        self.binding['scope']['dataClass'] = 'production'; put(self.scope / r.storage.MARKER, self.binding)
        with self.assertRaises(ValueError): self.backend.plan()
        self.binding['scope']['dataClass'] = 'synthetic'; put(self.scope / r.storage.MARKER, self.binding)
        self.native['inputs'] = {key: self.native['inputs'][key] for key in r.journal.CORE_INPUTS}
        self.save_native(); self.backend.expected = r.file_sha(self.root / '.install-intent.json')
        with self.assertRaises(ValueError): self.backend.plan()

    def test_links_special_files_hardlinks_and_unsafe_parent_refused(self):
        outside = self.base / 'untouched'; put(outside, b'foreign data')
        alias = self.blobs / 'alias'; alias.symlink_to(outside)
        with self.assertRaises((ValueError, OSError)): self.backend.plan()
        alias.unlink(); os.link(outside, alias)
        with self.assertRaises(ValueError): self.backend.plan()
        alias.unlink(); os.mkfifo(alias)
        with self.assertRaises(ValueError): self.backend.plan()
        alias.unlink(); self.volumes.chmod(0o777)
        with self.assertRaises(ValueError): self.backend.plan()
        self.assertEqual(outside.read_bytes(), b'foreign data')

    def test_foreign_cache_overlapping_and_unclassified_bind_roots_rejected(self):
        original = json.loads(json.dumps(self.ir))
        for path in (self.base / 'foreign', Path(self.domains[0]['graphRoot']), self.blobs / 'overlap'):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.ir['volumes']['postgres']['hostPath'] = str(path); self.rebind_ir()
            with self.assertRaises(ValueError): self.backend.plan()
        self.ir = original
        self.ir['services']['content']['volumes'].append('/private/cache:/cache')
        self.rebind_ir()
        with self.assertRaises(ValueError): self.backend.plan()

    def test_rootless_copy_resolves_actual_data_not_seed_or_graph(self):
        actual = Path(self.domains[0]['volumeRoot']) / 'blobs'; actual.mkdir(parents=True, mode=0o700)
        put(actual / 'real.bin', b'actual selected rootless blob')
        self.ir['services']['content'].update(placement='rootless', rootlessDomain='identity')
        self.rebind_ir()
        plan = self.backend.plan()
        self.assertIn(str(actual), plan['selection']['roots'])
        self.assertNotIn(str(self.blobs), plan['selection']['roots'])
        self.assertNotIn(self.domains[0]['graphRoot'], plan['selection']['roots'])

    def test_standalone_caddy_logs_and_read_only_public_trust_are_exact_roots(self):
        ca = self.volumes / 'caddy_ca'; ca.mkdir(mode=0o700)
        logs = self.volumes / '_logs/caddy'; logs.mkdir(parents=True, mode=0o700)
        put(ca / 'caddy-ca.crt', b'synthetic public CA certificate fixture')
        put(logs / 'access.log', b'synthetic redacted access entry')
        self.ir['volumes']['caddy_ca'] = {'hostPath': str(ca), 'rootlessAccess': 'read-only'}
        self.ir['services']['caddy'] = {'placement': 'rootful', 'volumes': [str(logs) + ':/var/log/caddy']}
        self.ir['services']['content']['volumes'].append(str(ca / 'caddy-ca.crt') + ':/ca.crt:ro')
        put(self.release / 'podman-domains.json', {'caddyLogRoot': str(logs)})
        self.rebind_ir()
        roots = self.backend.plan()['selection']['roots']
        self.assertIn(str(logs), roots); self.assertIn(str(ca), roots)
        self.ir['services']['content']['volumes'][-1] = str(ca / 'caddy-ca.crt') + ':/ca.crt:rw'
        self.rebind_ir()
        with self.assertRaises(ValueError): self.backend.plan()

    def test_count_byte_and_extended_metadata_bounds(self):
        with patch.object(r, 'MAX_ENTRIES', 2):
            with self.assertRaises(ValueError): self.backend.plan()
        with patch.object(r, 'MAX_BYTES', 8):
            with self.assertRaises(ValueError): self.backend.plan()
        with patch.object(r.os, 'listxattr', return_value=['user.fixture']):
            with self.assertRaises(ValueError): self.backend.plan()

    def test_wrong_key_and_authenticated_ciphertext_tamper_preserve_original(self):
        self.backup(); before = self.originals()
        wrong = self.key_dir / 'wrong'; put(wrong, b'wrong-key')
        with self.assertRaises(ValueError): self.restore(key=wrong)
        self.assertEqual(self.originals(), before)
        row = r.strict(r.read_file(self.backend.intent, private=True)); self.assertEqual(row['phase'], 'staging-failed')
        raw = bytearray(self.archive.read_bytes()); raw[-100] ^= 1; self.archive.write_bytes(raw)
        with self.assertRaises(ValueError): self.restore()
        self.assertEqual(self.originals(), before)
        self.assertFalse(list(self.backend.state.rglob('authenticated.tar')))

    def test_ciphertext_cas_and_separately_retained_key(self):
        self.backup(); before = self.originals()
        with self.assertRaises(ValueError): self.restore(digest='0' * 64)
        colocated = self.archive_dir / 'key'; put(colocated, b'fixture-key')
        with self.assertRaises(ValueError): self.restore(key=colocated)
        self.assertEqual(self.originals(), before)

    def test_archive_cannot_live_inside_selected_scope_or_native_root(self):
        for parent in (self.scope, self.root):
            with self.assertRaises(ValueError):
                self.backend.backup(parent / 'backup.age', 'age1' + 'q' * 58, self.op(), self.approve)
        self.assertEqual(self.approvals, [])

    def test_manifest_traversal_foreign_duplicate_and_hash_mismatch(self):
        for mutation in ('traversal', 'foreign', 'duplicate', 'hash', 'selection'):
            with self.subTest(mutation=mutation):
                if self.archive.exists(): self.archive.unlink()
                self.backup(); before = self.originals()
                def change(manifest, items):
                    target = next(row for row in manifest['entries'] if row['kind'] == 'file' and row['name'].startswith('payload/'))
                    if mutation == 'traversal': target['name'] = 'payload/0/../../escape'
                    elif mutation == 'foreign': target['name'] = 'payload/999/foreign'
                    elif mutation == 'duplicate': target['name'] = manifest['entries'][0]['name']
                    elif mutation == 'hash': target['sha256'] = '0' * 64
                    else: manifest['selection']['scope'] = str(self.base / 'foreign')
                self.repack(change)
                with self.assertRaises(ValueError): self.restore()
                self.assertEqual(self.originals(), before)
                self.assertFalse((self.base / 'escape').exists())

    def test_unlisted_symlink_hardlink_pax_and_large_header_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.XHDTYPE):
            with self.subTest(kind=kind):
                if self.archive.exists(): self.archive.unlink()
                self.backup(); before = self.originals()
                def extra(tar):
                    item = tarfile.TarInfo('payload/0/foreign'); item.type = kind
                    item.linkname = '/outside'; tar.addfile(item)
                self.repack(tar_extra=extra)
                with self.assertRaises(ValueError): self.restore()
                self.assertEqual(self.originals(), before)
        item = tarfile.TarInfo('oversized'); item.size = r.MAX_BYTES + 1
        reader = r.ArchiveReader(io.BytesIO(item.tobuf(format=tarfile.USTAR_FORMAT)))
        with self.assertRaises(ValueError): reader.next()

    def test_swap_failure_restores_all_originals_without_restart(self):
        self.backup(); self.changed(); before = self.originals()
        native_rename = r.rename
        count = [0]
        def failing_rename(source, destination):
            if Path(source).name == 'new':
                count[0] += 1
                if count[0] == 2: raise OSError('synthetic second root swap failure')
            return native_rename(source, destination)
        with patch.object(r, 'rename', side_effect=failing_rename):
            with self.assertRaises(OSError): self.restore()
        self.assertEqual(self.originals(), before)
        row = r.strict(r.read_file(self.backend.intent, private=True))
        self.assertEqual(row['phase'], 'originals-restored'); self.assertFalse(row['restart'])

    def test_pre_swap_inventory_cas_failure_preserves_originals(self):
        self.backup(); before = self.originals()
        stage = self.backend.stage
        def drifting_stage(*args):
            value = stage(*args)
            put(self.db / 'identity.db', b'external drift, preserve this')
            return value
        with patch.object(self.backend, 'stage', side_effect=drifting_stage):
            with self.assertRaises(ValueError): self.restore()
        self.assertEqual((self.db / 'identity.db').read_bytes(), b'external drift, preserve this')
        self.assertEqual((self.blobs / 'object.bin').read_bytes(), before[1])

    def test_interrupted_swap_requires_exact_journal_cas_and_recovery_approval(self):
        self.backup(); self.changed(); before = self.originals()
        native_rename = r.rename
        def crash(source, destination):
            if Path(source).name == 'new': raise OSError('synthetic crash after original rename')
            return native_rename(source, destination)
        with patch.object(r, 'rename', side_effect=crash), \
             patch.object(self.backend, 'rollback', side_effect=OSError('synthetic process death')):
            with self.assertRaises(OSError): self.restore()
        row = r.strict(r.read_file(self.backend.intent, private=True))
        self.assertEqual(row['phase'], 'swapping')
        with self.assertRaises(ValueError): self.restore()
        with self.assertRaises(ValueError): self.backend.recover('0' * 64, self.approve)
        digest = r.file_sha(self.backend.intent)
        with self.assertRaises(ValueError): self.backend.recover(digest, lambda request: {})
        result = self.backend.recover(digest, self.approve)
        self.assertTrue(result['originalsRestored']); self.assertFalse(result['restart'])
        self.assertEqual(self.originals(), before)

    def test_interrupted_data_root_rename_and_receipt_projection_gap_recover(self):
        self.backup(); self.changed(); before = self.originals()
        native_rename = r.rename
        def crash(source, destination):
            if Path(source).name == 'new' and Path(destination) == self.db:
                raise OSError('synthetic crash with identity DB root absent')
            return native_rename(source, destination)
        with patch.object(r, 'rename', side_effect=crash), \
             patch.object(self.backend, 'rollback', side_effect=OSError('synthetic death')):
            with self.assertRaises(OSError): self.restore()
        self.assertFalse(self.db.exists())
        row = r.strict(r.read_file(self.backend.intent, private=True))
        transaction = self.backend.state / row['request']['operationId']
        receipt = dict(row, phase='committed')
        put(transaction / 'receipt.json', receipt)
        result = self.backend.recover(r.file_sha(self.backend.intent), self.approve)
        self.assertTrue(result['originalsRestored']); self.assertEqual(self.originals(), before)

    def test_interrupted_staging_has_cas_recovery_without_any_data_swap(self):
        self.backup(); before = self.originals()
        record = self.backend.record
        def crash_record(row, transaction):
            if row['phase'] == 'staging-failed': raise OSError('synthetic process death')
            return record(row, transaction)
        with patch.object(self.backend, 'decrypt', side_effect=OSError('interrupted decryption')), \
             patch.object(self.backend, 'record', side_effect=crash_record):
            with self.assertRaises(OSError): self.restore()
        row = r.strict(r.read_file(self.backend.intent, private=True))
        self.assertEqual(row['phase'], 'staging')
        transaction = self.backend.state / row['request']['operationId']
        # The new backend has no persistent plaintext spool. An unrelated file
        # using the historical name is not inferred/adopted/deleted on recovery.
        spool = transaction / 'authenticated.tar'; put(spool, b'unrelated synthetic sentinel')
        digest = r.file_sha(self.backend.intent)
        with self.assertRaises(ValueError): self.backend.recover(digest, lambda request: {})
        self.assertTrue(spool.exists())
        self.assertTrue(self.backend.recover(digest, self.approve)['originalsRestored'])
        self.assertTrue(spool.exists()); self.assertEqual(self.originals(), before)

    def test_recovery_rejects_changed_preserved_original_and_foreign_journal_roots(self):
        self.backup(); self.changed()
        native_rename = r.rename
        def crash(source, destination):
            if Path(source).name == 'new': raise OSError('synthetic interruption')
            return native_rename(source, destination)
        with patch.object(r, 'rename', side_effect=crash), \
             patch.object(self.backend, 'rollback', side_effect=OSError('synthetic death')):
            with self.assertRaises(OSError): self.restore()
        row = r.strict(r.read_file(self.backend.intent, private=True))
        original = Path(row['stages'][0]['area']) / 'original/stack.env'
        prior = original.read_bytes(); put(original, b'externally changed original: preserve')
        with self.assertRaises(ValueError):
            self.backend.recover(r.file_sha(self.backend.intent), self.approve)
        self.assertEqual(original.read_bytes(), b'externally changed original: preserve')
        put(original, prior)
        transaction = self.backend.state / row['request']['operationId']
        row['stages'][0]['area'] = str(self.base / 'unrelated')
        put(self.backend.intent, row); put(transaction / 'receipt.json', row)
        with self.assertRaises(ValueError):
            self.backend.recover(r.file_sha(self.backend.intent), self.approve)
        self.assertFalse((self.base / 'unrelated').exists())

    def test_mountpoints_reserve_owner_and_noreplace_guards(self):
        with patch.object(r, 'mount_points', return_value={self.blobs / 'nested'}):
            with self.assertRaises(ValueError): self.backend.plan()
        with patch.object(r, 'MIN_FREE_BYTES', 2**100):
            with self.assertRaises(ValueError): self.backup()
        self.assertFalse(self.archive.exists())
        with patch.object(r, 'OWNER', -1):
            with self.assertRaises(ValueError): self.backend.plan()
        a, b = self.base / 'rename-source', self.base / 'rename-destination'
        put(a, b'source'); put(b, b'foreign destination')
        with self.assertRaises(FileExistsError): r.rename(a, b)
        self.assertEqual(a.read_bytes(), b'source'); self.assertEqual(b.read_bytes(), b'foreign destination')

    def test_real_native_storage_authority_import_checks_standalone_hashes(self):
        # Exercise the actual imported owning authority, not its fixture stub.
        manifest = {'site': 'fixture', 'deploymentMode': 'standalone',
                    'installerStateRoot': '/var/lib/webservices', 'storageScope': self.binding['scope']}
        put(self.release / 'site/manifest.json', manifest)
        for name in ('site/agent-vm.json', 'site/agent-vm.provenance.json'):
            (self.release / name).unlink()
        put(self.release / 'podman-domains.json', {'deploymentMode': 'standalone',
            'storageScope': self.binding['scope'], 'domains': self.domains})
        put(self.release / 'source-provenance.json',
            {'manifestSha256': r.file_sha(self.release / 'site/manifest.json')})
        put(self.release / 'bundle.json', {'deploymentMode': 'standalone', 'backend': 'podman',
            'sourceProvenanceSha256': r.file_sha(self.release / 'source-provenance.json'),
            'irSha256': r.file_sha(self.release / 'stack.ir.json')})
        scope, operator, actual = self.native_storage_authority(self.release)
        self.assertEqual(scope, self.scope); self.assertEqual(actual, self.binding)
        put(self.release / 'source-provenance.json', {'manifestSha256': '0' * 64})
        with self.assertRaises(ValueError): self.native_storage_authority(self.release)

    def test_native_metadata_root_must_equal_pinned_manifest(self):
        put(self.release / 'site/manifest.json', {'installerStateRoot': '/var/lib/foreign'})
        self.native['inputs'] = r.journal.fingerprint(self.release)
        self.save_native(); self.backend.expected = r.file_sha(self.root / '.install-intent.json')
        with self.assertRaises(ValueError): self.backend.plan()

    def test_archive_duplicate_json_and_trailing_concatenation_refused(self):
        with self.assertRaises(ValueError): r.strict(b'{"a":1,"a":2}')
        with self.assertRaises(ValueError):
            r.ArchiveReader(io.BytesIO(b'\0' * 1024 + b'foreign archive')).next()
        with self.assertRaises(ValueError):
            r.ArchiveReader(io.BytesIO(b'truncated')).next()

    def test_backup_post_inventory_drift_never_publishes(self):
        inventory = self.backend.inventory; calls = [0]
        def drift():
            calls[0] += 1
            if calls[0] == 2: put(self.db / 'identity.db', b'concurrent synthetic drift')
            return inventory()
        with patch.object(self.backend, 'inventory', side_effect=drift):
            with self.assertRaises(ValueError): self.backup()
        self.assertFalse(self.archive.exists())
        self.assertFalse(list(self.archive_dir.glob('.encrypted-recovery-*')))

    def test_streamed_bytes_must_match_inventory_not_just_before_after_scans(self):
        original_open = r.nofollow_fd
        substitute = self.base / 'transient-content'
        put(substitute, b'X' * (self.db / 'identity.db').stat().st_size)
        def change_only_stream(path):
            if Path(path) == self.db / 'identity.db': return original_open(substitute)
            return original_open(path)
        with patch.object(r, 'nofollow_fd', side_effect=change_only_stream):
            with self.assertRaises(ValueError): self.backup()
        self.assertFalse(self.archive.exists())
        self.assertEqual((self.db / 'identity.db').read_bytes(), b'synthetic alice identity')

    def test_decrypt_bounds_and_archive_or_key_links_preserve_selected_roots(self):
        self.backup(); before = self.originals()
        with patch.object(r, 'MAX_ARCHIVE', 16):
            with self.assertRaises(ValueError): self.restore()
        self.assertEqual(self.originals(), before)
        linked_key = self.key_dir / 'linked'; linked_key.symlink_to(self.key)
        with self.assertRaises((ValueError, OSError)): self.restore(key=linked_key)
        linked_key.unlink(); os.link(self.key, linked_key)
        with self.assertRaises(ValueError): self.restore()
        linked_key.unlink()
        alias = self.archive_dir / 'archive-alias'; alias.symlink_to(self.archive)
        with self.assertRaises((ValueError, OSError)):
            self.backend.restore(alias, r.file_sha(self.archive), self.key, self.op(), self.approve)
        self.assertEqual(self.originals(), before)

    def actual_model(self):
        """Virtual numeric ownership ONLY; real temp inodes, hashes, FDs, swaps.

        No host account/range/config lookup and no privileged chown. The lease
        and root receipt are synthetic integration fixtures, NOT host evidence.
        """
        self.virtual = {}
        native_fstat, native_lstat = os.fstat, Path.lstat
        native_getxattr, native_listxattr = os.getxattr, os.listxattr
        def mapped(info):
            values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
            values.update(self.virtual.get((info.st_dev, info.st_ino), {'st_uid': 0, 'st_gid': 0}))
            return SimpleNamespace(**values)
        def fstat(fd):
            info = native_fstat(fd)
            # Only fixture FDs have virtual ownership; /proc and /tmp ancestors
            # remain actual kernel metadata.
            try: node = Path(os.readlink('/proc/self/fd/' + str(fd)))
            except OSError: return info
            return mapped(info) if node.is_relative_to(self.base) else info
        def lstat(node, *args, **kwargs):
            info = native_lstat(node, *args, **kwargs)
            return mapped(info) if node.is_relative_to(self.base) else info
        def chown(node, uid, gid, **unused):
            info = native_lstat(Path(node))
            self.virtual[(info.st_dev, info.st_ino)] = {'st_uid': uid, 'st_gid': gid}
        def fchown(fd, uid, gid):
            node = Path(os.readlink('/proc/self/fd/' + str(fd)))
            self.assertTrue(node.is_relative_to(self.base))
            info = native_fstat(fd)
            self.virtual[(info.st_dev, info.st_ino)] = {'st_uid': uid, 'st_gid': gid}
        def owner(node, uid, gid):
            info = native_lstat(node)
            self.virtual[(info.st_dev, info.st_ino)] = {'st_uid': uid, 'st_gid': gid}
        self.scope.chmod(0o2770); owner(self.scope, 1000, 4321)
        self.scope_inode = (native_lstat(self.scope).st_dev, native_lstat(self.scope).st_ino)
        struct_acl = __import__('struct')
        self.scope_acl = struct_acl.pack('<I', 2) + b''.join(struct_acl.pack('<HHI', *row) for row in (
            [(1, 7, 0xffffffff)] + [(2, 1, uid) for uid in range(780, 787)]
            + [(4, 7, 0xffffffff), (16, 7, 0xffffffff), (32, 0, 0xffffffff)]))
        def getxattr(fd, name, *args, **kwargs):
            info = native_fstat(fd) if isinstance(fd, int) else native_lstat(Path(fd))
            if (info.st_dev, info.st_ino) == self.scope_inode and name == 'system.posix_acl_access':
                return self.scope_acl
            return native_getxattr(fd, name, *args, **kwargs)
        def listxattr(fd, *args, **kwargs):
            info = native_fstat(fd) if isinstance(fd, int) else native_lstat(Path(fd))
            if (info.st_dev, info.st_ino) == self.scope_inode: return ['system.posix_acl_access']
            return native_listxattr(fd, *args, **kwargs)
        self.homes = self.base / 'homes'; self.homes.mkdir(mode=0o700)
        for mocking in (patch.object(r, 'OWNER', 0), patch.object(r, 'HOME_ROOT', self.homes),
                        patch.object(r.os, 'fstat', side_effect=fstat), patch.object(Path, 'lstat', lstat),
                        patch.object(r.os, 'chown', side_effect=chown),
                        patch.object(r.os, 'fchown', side_effect=fchown),
                        patch.object(r.os, 'getxattr', side_effect=getxattr),
                        patch.object(r.os, 'listxattr', side_effect=listxattr),
                        patch.object(r.storage, 'marker', side_effect=lambda scope, binding: None)):
            mocking.start(); self.addCleanup(mocking.stop)
        self.domains, actors, configs = [], [], []
        for index, name in enumerate(('identity', 'apps', 'search', 'ci', 'tests', 'models', 'edge')):
            uid = 780 + index; user = 'webservices-lab-' + name; start = 200000 + index * 65536
            domain = {'name': name, 'user': user, 'uid': uid}
            for key in ('stateRoot', 'graphRoot', 'volumeRoot'):
                node = self.scope / 'domains' / name / key
                node.mkdir(parents=True, exist_ok=True, mode=0o700); node.chmod(0o700)
                owner(node, uid, uid); domain[key] = str(node)
            # The ancestry is explicitly operator-owned, not root-adopted.
            for node in (self.scope / 'domains', self.scope / 'domains' / name):
                node.chmod(0o2770); owner(node, 1000, 4321)
            actor = dict(name=name, user=user, uid=uid, gid=uid, start=start, count=65536)
            actors.append(actor); self.domains.append(domain)
            home = self.homes / user; home.mkdir(mode=0o700); owner(home, uid, uid)
            for node in (home / '.config', Path(domain['stateRoot']) / 'releases' / self.release.name / 'runtime'):
                node.mkdir(parents=True, mode=0o700)
                put(node / 'selected.conf', b'exact synthetic source configuration')
                owner(node, uid, uid); owner(node / 'selected.conf', uid, uid)
                parent = node.parent
                while parent.is_relative_to(domain['stateRoot']) and parent != Path(domain['stateRoot']):
                    parent.chmod(0o700); owner(parent, uid, uid); parent = parent.parent
                rows = r.tree_entries(node, 'payload/0', [0, 0])
                configs.append(dict(domain=name, path=str(node), entriesSha256=r.sha(r.canonical(r.content_rows(rows)))))
        self.binding['domains'] = self.domains
        self.binding['roots'] = sorted(d[k] for d in self.domains for k in ('stateRoot', 'graphRoot', 'volumeRoot'))
        put(self.scope / r.storage.MARKER, self.binding)
        seed_db = self.db
        self.db = Path(self.domains[0]['volumeRoot']) / 'postgres'; self.db.mkdir(mode=0o700)
        put(self.db / 'identity.db', b'synthetic alice identity')
        owner(self.db, 780, 780); owner(self.db / 'identity.db', actors[0]['start'] + 999, actors[0]['start'] + 888)
        owner(self.blobs / 'object.bin', actors[1]['start'] + 50, actors[1]['start'] + 60)
        # Shared hostPath is actually consumed by rootful AND rootless services.
        self.ir['services']['postgres'].update(placement='rootless', rootlessDomain='identity')
        self.ir['services']['content'].update(placement='rootless', rootlessDomain='apps')
        self.ir['volumes']['blobs']['rootlessStrategy'] = 'shared'
        self.ir['services']['rootful-blob-reader'] = {'placement': 'rootful', 'volumes': ['blobs:/objects:ro']}
        self.rebind_ir()
        roots = r.selected_roots(self.release, self.scope, self.binding)
        paths = {self.scope, self.release}
        def below(node):
            while node != self.scope:
                paths.add(node); node = node.parent
        for domain in self.domains:
            for key in ('stateRoot', 'graphRoot', 'volumeRoot'): below(Path(domain[key]))
        for node in roots[1:]: below(node.parent)
        for config in configs:
            node = Path(config['path'])
            if node.is_relative_to(self.scope): below(node.parent)
            else: paths.add(node.parent)
        directories = {}
        for node in paths:
            fd = r.nofollow_fd(node)
            try: directories[str(node)] = r.custody_record(fd)
            finally: os.close(fd)
        self.proof = dict(schemaVersion=1, operatorUid=1000, operatorGid=4321,
                          allocationSha256={'subuid': 'a' * 64, 'subgid': 'b' * 64},
                          actors=actors, directories=directories, configurationRoots=configs)
        self.native['recoveryCustody'] = self.proof
        self.save_native(); self.backend.expected = r.file_sha(self.root / '.install-intent.json')
        self.lease_checks = []
        def verify(request):
            self.lease_checks.append(request)
            if not self.quiesced: raise ValueError('Synthetic lease revoked')
            self.assertEqual(request['custodySha256'], r.sha(r.canonical(self.proof)))
            self.assertEqual(request['allocationSha256'], self.proof['allocationSha256'])
        self.backend.lease = SimpleNamespace(verify_recovery=verify)
        self.seed_db = seed_db

    def reseal_proof(self):
        self.native['recoveryCustody'] = self.proof
        self.save_native(); self.backend.expected = r.file_sha(self.root / '.install-intent.json')

    def test_actual_operator2770_seven_actors_mapped_identity_and_shared_blob_roundtrip(self):
        self.actual_model(); original = self.originals()
        seed = (self.seed_db / 'identity.db').read_bytes()
        self.backup(); self.changed()
        result = self.restore()
        self.assertTrue(result['restored']); self.assertFalse(result['installedAcceptance'])
        self.assertEqual(self.originals(), original)
        self.assertEqual((self.seed_db / 'identity.db').read_bytes(), seed)
        self.assertTrue(self.lease_checks)
        self.assertFalse(list(self.base.rglob('authenticated.tar')))
        self.assertEqual(self.scope.stat().st_mode & 0o7777, 0o2770)

    def test_actual_model_requires_receipt_bound_lease_and_exact_custody(self):
        self.actual_model()
        self.backend.lease = None
        with self.assertRaises(ValueError): self.backend.plan()
        self.backend.lease = SimpleNamespace(verify_recovery=lambda request: True)
        with self.assertRaises(ValueError): self.backend.plan()
        self.backend.lease = SimpleNamespace(verify_recovery=lambda request: None)
        self.proof['directories'][str(self.scope)]['ino'] += 1; self.reseal_proof()
        with self.assertRaises(ValueError): self.backend.plan()
        self.assertFalse(self.archive.exists())

    def test_actual_cross_domain_mapped_or_unclaimed_owner_and_ranges_fail_closed(self):
        self.actual_model()
        file = self.db / 'identity.db'; info = file.lstat(); key = (info.st_dev, info.st_ino)
        good = dict(self.virtual[key])
        for uid in (self.proof['actors'][1]['start'] + 999, 99999999, 1000, 781):
            self.virtual[key] = {'st_uid': uid, 'st_gid': good['st_gid']}
            with self.assertRaises(ValueError): self.backend.plan()
        self.virtual[key] = {'st_uid': good['st_uid'], 'st_gid': self.proof['actors'][1]['start'] + 888}
        with self.assertRaises(ValueError): self.backend.plan()
        self.virtual[key] = good
        self.proof['actors'][1]['start'] = self.proof['actors'][0]['start']; self.reseal_proof()
        with self.assertRaises(ValueError): self.backend.plan()

    def test_actual_scope_acl_foreign_mount_config_hash_and_lease_revocation(self):
        self.actual_model()
        original_acl = self.scope_acl
        self.scope_acl = self.scope_acl.replace(__import__('struct').pack('<HHI', 2, 1, 780),
                                                 __import__('struct').pack('<HHI', 2, 3, 780))
        with self.assertRaises(ValueError): self.backend.plan()
        # Even a root-sealed receipt cannot authorize an actor write ACL.
        self.proof['directories'][str(self.scope)]['acl'] = self.scope_acl.hex(); self.reseal_proof()
        with self.assertRaises(ValueError): self.backend.plan()
        self.scope_acl = original_acl
        self.proof['directories'][str(self.scope)]['acl'] = self.scope_acl.hex(); self.reseal_proof()
        node = Path(self.domains[0]['volumeRoot'])
        self.proof['directories'][str(node)]['mountId'] += 1; self.reseal_proof()
        with self.assertRaises(ValueError): self.backend.plan()
        self.proof['directories'][str(node)]['mountId'] -= 1; self.reseal_proof()
        config = Path(self.proof['configurationRoots'][0]['path']) / 'selected.conf'
        old = config.read_bytes(); config.write_bytes(b'foreign source drift')
        with self.assertRaises(ValueError): self.backend.plan()
        config.write_bytes(old)
        self.quiesced = False
        with self.assertRaises(ValueError): self.backend.plan()
        self.assertEqual(self.approvals, [])

    def test_actual_wrong_key_tamper_and_stopped_lease_loss_preserve_mapped_data(self):
        self.actual_model(); self.backup(); before = self.originals()
        wrong = self.key_dir / 'wrong'; put(wrong, b'not-the-retained-key')
        with self.assertRaises(ValueError): self.restore(key=wrong)
        self.assertEqual(self.originals(), before)
        raw = bytearray(self.archive.read_bytes()); raw[-100] ^= 1; self.archive.write_bytes(raw)
        with self.assertRaises(ValueError): self.restore()
        self.assertEqual(self.originals(), before)
        # A trusted approval callback is not itself a stopped lease verifier.
        self.archive.unlink()
        def revoked(request):
            self.quiesced = False
            return request
        with self.assertRaises(ValueError):
            self.backend.backup(self.archive, 'age1' + 'q' * 58, self.op(), revoked)
        self.assertFalse(self.archive.exists()); self.assertEqual(self.originals(), before)

    def test_actual_interrupted_mapped_data_swap_requires_native_and_recovery_cas(self):
        self.actual_model(); self.backup(); self.changed(); before = self.originals()
        swap = self.backend.swap
        def crash(source, destination):
            if Path(source).name == 'new' and destination == self.db:
                raise OSError('synthetic death with actual-model identity root absent')
            return swap(source, destination)
        with patch.object(self.backend, 'swap', side_effect=crash), \
             patch.object(self.backend, 'rollback', side_effect=OSError('synthetic death')):
            with self.assertRaises(OSError): self.restore()
        self.assertFalse(self.db.exists())
        with self.assertRaises(ValueError): self.backend.recover('0' * 64, self.approve)
        digest = r.file_sha(self.backend.intent)
        self.assertTrue(self.backend.recover(digest, self.approve)['originalsRestored'])
        self.assertEqual(self.originals(), before)

    def test_actual_parent_replacement_is_not_adopted_or_swapped(self):
        self.actual_model(); self.backup(); before = self.originals()
        stage = self.backend.stage
        displaced = self.scope / 'displaced-private-volume-parent'
        def drift(*args):
            result = stage(*args)
            parent = self.db.parent
            parent.rename(displaced)
            parent.mkdir(mode=0o700)
            put(parent / 'foreign-sentinel', b'never adopt or mutate this replacement')
            return result
        with patch.object(self.backend, 'stage', side_effect=drift):
            with self.assertRaises(ValueError): self.restore()
        self.assertEqual((self.db.parent / 'foreign-sentinel').read_bytes(), b'never adopt or mutate this replacement')
        self.assertEqual((displaced / 'postgres/identity.db').read_bytes(), before[0])
        self.assertFalse(self.db.exists())

    def test_archive_cannot_restore_foreign_mapped_owner_even_with_authenticated_ciphertext(self):
        self.actual_model(); self.backup(); before = self.originals()
        def foreign(manifest, items):
            row = next(row for row in manifest['entries'] if row.get('sha256') == r.sha(before[0]))
            row['uid'] = self.proof['actors'][1]['start'] + 123
            for item, _ in items:
                if item.name == row['name']: item.uid = row['uid']
        self.repack(foreign)
        with self.assertRaises(ValueError): self.restore()
        self.assertEqual(self.originals(), before)

    def test_backup_size_matches_restore_memory_bound_and_binary_hash_cas(self):
        manifest, _ = self.backend.inventory()
        size = self.backend.archive_bytes(manifest)
        self.backup()
        self.assertEqual(size, len(self.archive.read_bytes()) - 41)
        self.archive.unlink()
        with patch.object(r, 'MAX_AUTHENTICATED_BYTES', size - 1):
            with self.assertRaises(ValueError): self.backup()
        self.assertFalse(self.archive.exists())
        def replace_binary(request):
            put(self.age, b'#!/usr/bin/python3\nraise RuntimeError("unapproved")\n', 0o700)
            return request
        with self.assertRaises(ValueError):
            self.backend.backup(self.archive, 'age1' + 'q' * 58, self.op(), replace_binary)
        self.assertFalse(self.archive.exists())

    def test_private_marker_mask0_acl_is_preserved_only_as_reference(self):
        marker = self.scope / r.storage.MARKER; undefined = 0xffffffff
        acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *entry) for entry in (
            (1, 6, undefined), (2, 7, 1000), (4, 7, undefined), (16, 0, undefined), (32, 0, undefined)))
        os.setxattr(marker, 'system.posix_acl_access', acl)
        before = r.stable(marker.stat()); original = marker.read_bytes()
        with self.assertRaises(ValueError): r.tree_entries(marker, 'marker', [0, 0])
        rows = r.tree_entries(marker, 'marker', [0, 0], private_marker=True)
        self.assertEqual(rows[0]['sha256'], r.sha(original))
        self.assertEqual(os.getxattr(marker, 'system.posix_acl_access'), acl)
        self.assertEqual(r.stable(marker.stat()), before)
        os.setxattr(marker, 'system.posix_acl_access', acl[:-16] + struct.pack('<HHI', 16, 4, undefined) + struct.pack('<HHI', 32, 0, undefined))
        with self.assertRaises(ValueError): r.tree_entries(marker, 'marker', [0, 0], private_marker=True)

    def test_finance_exact_readonly_source_is_reference_not_data_or_legacy_permit(self):
        self.ir['services']['firefly-identity-check'] = {'placement': 'rootful', 'volumes': []}
        self.ir['services']['keycloak-configure'] = dict(placement='rootful', lifecycle='oneshot',
            environment={'FIREFLY_NATIVE_OWNERSHIP_FILE': '/run/p0-finance/input.json'},
            volumes=['/var/lib/webservices-native-finance:/run/p0-finance:ro'])
        self.rebind_ir()
        roots, classified = r.selected_roots(self.release, self.scope, self.binding, classified=True)
        self.assertNotIn(Path('/var/lib/webservices-native-finance'), roots)
        self.assertEqual(len([row for row in classified if row['kind'] == 'root-control-reference']), 1)
        with self.assertRaisesRegex(ValueError, 'historical recovery admission'): self.backend.plan()
        self.ir['services']['keycloak-configure']['volumes'][0] = '/var/lib/webservices-native-finance:/run/p0-finance:rw'
        self.rebind_ir()
        with self.assertRaises(ValueError): r.selected_roots(self.release, self.scope, self.binding, classified=True)

    def test_declared_unused_named_data_refuses_instead_of_omitting(self):
        self.ir['volumes']['unclaimed'] = {'hostPath': str(self.scope / 'unclaimed')}
        self.rebind_ir()
        with self.assertRaisesRegex(ValueError, 'no selected ownership/consumer'): self.backend.plan()

    def test_native_failed_intent_not_recovery_authority_but_retired_failed_is(self):
        for phase in ('failed', 'retired-failed'):
            self.native['phase'] = phase; self.save_native()
            self.backend.expected = r.file_sha(self.root / '.install-intent.json')
            if phase == 'failed':
                with self.assertRaises(ValueError): self.backend.plan()
            else: self.assertFalse(self.backend.plan()['installedAcceptance'])

    def test_actual_cross_domain_private_shared_path_and_unclaimed_config_refused(self):
        self.actual_model()
        self.ir['volumes']['blobs']['hostPath'] = str(self.db)
        self.rebind_ir()
        with self.assertRaises(ValueError): self.backend.plan()
        self.ir['volumes']['blobs']['hostPath'] = str(self.blobs); self.rebind_ir()
        self.proof['configurationRoots'][0]['path'] = str(self.homes / 'unclaimed/.config')
        self.reseal_proof()
        with self.assertRaises(ValueError): self.backend.plan()
        self.assertEqual(self.approvals, [])

    def test_metadata_root_private_mode_required_without_chmod_adoption(self):
        self.root.chmod(0o755)
        with self.assertRaises(ValueError): self.backend.plan()
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o755)

    def test_full_payload_contract_covers_one_gib_fixture_without_unbounded_memory(self):
        manifest, _ = self.backend.inventory()
        manifest['entries'].append({'size': 1024 ** 3})
        size = self.backend.archive_bytes(manifest)
        self.assertGreater(size, 1024 ** 3)
        self.assertLessEqual(size, r.MAX_AUTHENTICATED_BYTES)
        self.assertEqual(r.MAX_AUTHENTICATED_BYTES, r.MAX_ARCHIVE)

    def test_authentication_memory_capacity_retains_sixteen_gib_physical_reserve(self):
        reserve = r.MIN_AUTHENTICATION_FREE_BYTES
        requested = 1024 ** 3
        for delta, allowed in ((0, True), (-1024, False)):
            text = 'MemAvailable: %d kB\n' % ((reserve + requested + delta) // 1024)
            with patch.object(r.Path, 'read_text', return_value=text):
                if allowed: self.backend.authentication_capacity(requested)
                else:
                    with self.assertRaisesRegex(ValueError, 'physical memory reserve'):
                        self.backend.authentication_capacity(requested)
        for text in ('', 'MemAvailable: invalid kB\n', 'MemAvailable: 999999999 bytes\n',
                     'MemAvailable: 999999999 kB\nMemAvailable: 999999999 kB\n'):
            with patch.object(r.Path, 'read_text', return_value=text):
                with self.assertRaises(ValueError): self.backend.authentication_capacity(requested)
        with self.assertRaises(ValueError): self.backend.authentication_capacity(-1)

    def test_restore_memory_pressure_during_decrypt_refuses_before_payload_swap(self):
        self.backup(); before = self.originals()
        with patch.object(self.backend, 'authentication_capacity',
                          side_effect=[None, ValueError('physical memory reserve')]) as capacity:
            with self.assertRaisesRegex(ValueError, 'physical memory reserve'): self.restore()
        self.assertEqual(capacity.call_count, 2)
        self.assertEqual(self.originals(), before)
        self.assertFalse(list(self.backend.state.rglob('authenticated.tar')))

    def test_anonymous_authenticated_archive_bound_never_spills_to_disk(self):
        self.backup(); before = self.originals()
        with patch.object(r, 'MAX_AUTHENTICATED_BYTES', 16):
            with self.assertRaises(ValueError): self.restore()
        self.assertEqual(self.originals(), before)
        self.assertFalse(list(self.backend.state.rglob('authenticated.tar')))

    def test_fake_age_failure_timeout_and_bad_binary_are_closed(self):
        put(self.age, b'#!/usr/bin/python3\nimport sys\nsys.exit(1)\n', 0o700)
        with self.assertRaises((ValueError, BrokenPipeError)): self.backup()
        self.assertFalse(self.archive.exists())
        put(self.age, b'#!/usr/bin/python3\nimport time\ntime.sleep(2)\n', 0o700)
        with patch.object(r, 'PROCESS_TIMEOUT', 0.05):
            with self.assertRaises((ValueError, BrokenPipeError, r.subprocess.SubprocessError)): self.backup()
        self.assertFalse(self.archive.exists())
        self.age.chmod(0o777)
        with self.assertRaises(ValueError): self.backup()


    def test_transport_socket_is_classified_never_opened_or_archived(self):
        self.ir['services']['runner'] = dict(placement='rootless', rootlessDomain='identity',
            volumes=['%t/podman/podman.sock:/run/podman.sock'])
        self.rebind_ir()
        roots, classification = r.selected_roots(self.release, self.scope, self.binding, classified=True)
        self.assertEqual(set(roots), {self.release / 'runtime', self.db, self.blobs})
        self.assertEqual(classification[-1]['kind'], 'transport-not-archived')
        self.ir['services']['runner']['placement'] = 'rootful'; self.rebind_ir()
        with self.assertRaises(ValueError): r.selected_roots(self.release, self.scope, self.binding)

    def test_ci_exact_state_leaf_included_but_entire_state_auth_and_cache_refuse(self):
        ci = dict(self.domains[0], name='ci-runner')
        ci['stateRoot'] = str(self.scope / 'ci/state'); ci['graphRoot'] = str(self.scope / 'ci/graph')
        ci['volumeRoot'] = str(self.scope / 'ci/volumes')
        self.binding['domains'].append(ci)
        leaf = Path(ci['stateRoot']) / 'forgejo-runner-ssh'; leaf.mkdir(parents=True, mode=0o700)
        self.ir['services']['runner'] = dict(placement='rootless', rootlessDomain='ci-runner', volumes=[str(leaf) + ':/ssh'])
        self.rebind_ir()
        self.assertIn(leaf, r.selected_roots(self.release, self.scope, self.binding))
        for path in (ci['stateRoot'], ci['graphRoot'], str(Path(ci['stateRoot']) / '.ssh')):
            self.ir['services']['runner']['volumes'] = [path + ':/bad']; self.rebind_ir()
            with self.assertRaisesRegex(ValueError, 'Unclassified'): r.selected_roots(self.release, self.scope, self.binding)

    def test_native_expected_namespace_rejects_unknown_name_before_content_open(self):
        unknown = self.blobs / 'credential'; unknown.symlink_to('/never-read')
        names = {'reference/0', 'reference/0/object.bin', 'reference/0/nested', 'reference/0/nested/document.txt'}
        with self.assertRaisesRegex(ValueError, 'Unclaimed configuration name'):
            r.tree_entries(self.blobs, 'reference/0', [0, 0], expected_names=names)


if __name__ == '__main__': unittest.main(verbosity=2)
