#!/usr/bin/env python3
"""Synthetic source/FD/OCI/control-plane tests. No native tools or host calls.

Workflow fixtures simulate numeric ownership ONLY inside a disposable root;
separate mocked-stat tests exercise production permissions. The trusted lease,
namespace executor, host reserves and chown of NEW fixture inodes are mocked.
Actual tar closure/config verification and source/full-inventory CAS stay live.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/export-selected-images.py'
SPEC = importlib.util.spec_from_file_location('selected_export_tests', SOURCE)
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def write_json(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(M.json_bytes(body)); path.chmod(0o600)
    return sha(path.read_bytes())


def fixture(path, text='synthetic immutable release layer'):
    stream = io.BytesIO()
    with __import__('tarfile').open(fileobj=stream, mode='w') as tar:
        entry = __import__('tarfile').TarInfo('usr/share/fixture.txt')
        data = text.encode(); entry.size = len(data); tar.addfile(entry, io.BytesIO(data))
    layer = stream.getvalue()
    config = json.dumps({'os': 'linux', 'architecture': 'amd64',
                         'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + sha(layer)]}}).encode()
    descriptor = lambda body, kind: {'mediaType': M.package.OCI + kind,
                                     'size': len(body), 'digest': 'sha256:' + sha(body)}
    manifest = json.dumps({'schemaVersion': 2, 'config': descriptor(config, 'config.v1+json'),
                           'layers': [descriptor(layer, 'layer.v1.tar')]}).encode()
    rows = {'oci-layout': b'{"imageLayoutVersion":"1.0.0"}',
            'index.json': json.dumps({'schemaVersion': 2,
                                      'manifests': [descriptor(manifest, 'manifest.v1+json')]}).encode()}
    for body in (config, manifest, layer): rows['blobs/sha256/' + sha(body)] = body
    with __import__('tarfile').open(path, 'w') as tar:
        for name, body in rows.items():
            entry = __import__('tarfile').TarInfo(name); entry.size = len(body)
            tar.addfile(entry, io.BytesIO(body))
    path.chmod(0o600)
    return 'sha256:' + sha(config)


class Lease:
    """MOCK trusted existing installer; never an admission implementation."""
    def __init__(self, case):
        self.case = case; self.plans = []; self.exited = []; self.alive = set()
        self.fail = None; self.mutate = None; self.namespace_bad = False; self.probe_mutate = None
        self.quiescent_calls = 0; self.lease_calls = 0

    def verify_export(self, request):
        if self.fail == 'manager': raise M.Refused('manager/API activation refusal')
        if self.fail == 'operation': raise M.Refused('canonical operation lease mismatch')
        if self.fail == 'foreign-range': raise M.Refused('foreign allocation overlap')
        if self.fail == 'foreign-writer': raise M.Refused('foreign group writer')
        if self.fail == 'lease-after-spawn' and self.plans: raise M.Refused('lease lost')

    def read_leases(self, scope_fd, marker_fd, graph_fds, request):
        assert stat.S_ISDIR(os.fstat(scope_fd).st_mode)
        assert stat.S_ISREG(os.fstat(marker_fd).st_mode)
        assert len(graph_fds) == 8
        self.lease_calls += 1
        if self.fail == 'storage-lease': raise M.Refused('own storage lease mismatch')

    def check_reserves(self, request):
        if self.fail == 'reserves': raise M.Refused('caller reserve floor')

    @contextlib.contextmanager
    def export_process(self, plan, guard):
        self.plans.append(plan)
        self.alive.update(('leader', 'pause-descendant'))
        lease = self
        class Runner:
            def probe(self):
                evidence = {key: plan[key] for key in ('namespace', 'graphRoot', 'driver', 'storageOptions', 'configSha256')} | {
                    'compatibilitySha256': 'c' * 64}
                if lease.probe_mutate: lease.probe_mutate(evidence)
                return evidence

            def run(self):
                target = Path(plan['archive'])
                shutil.copyfile(lease.case.wrong_archive if lease.fail == 'wrong-image' else lease.case.archive, target)
                target.chmod(0o600)
                # Leader exits while an owned pause helper remains. The lease
                # context MUST still cancel/reap it, also on guard exceptions.
                lease.alive.remove('leader')
                if lease.fail == 'partial':
                    with target.open('ab') as out: out.write(b'oversize' * 10000)
                if lease.mutate: lease.mutate()
                guard()
                if lease.fail == 'interrupt': raise InterruptedError('synthetic cancel')
                return None
        try:
            yield Runner()
        finally:
            # Simulates Main's bounded descendant lifetime, not process proof.
            if self.fail != 'leaked-pause': self.alive.clear()
            self.exited.append(plan['authority'])

    def verify_namespace(self, plan, evidence):
        if self.namespace_bad: raise M.Refused('namespace compatibility unproven')
        assert evidence['namespace'] == plan['namespace']

    def verify_quiescent(self, request):
        self.quiescent_calls += 1
        if self.alive: raise M.Refused('owned descendant remains')


class ExportWorkflow(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='selected-export-fixture-')
        self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        self.bundle = self.root / 'installer/releases/candidate'
        self.bundle.mkdir(parents=True)
        self.scope = self.root / 'scope'; self.scope.mkdir(mode=0o700)
        self.output = self.root / 'supply'; self.receipt_path = self.root / 'source.json'
        self.archive = self.root / 'synthetic.tar'; self.image = fixture(self.archive)
        self.wrong_archive = self.root / 'different.tar'; fixture(self.wrong_archive, 'different config bytes')
        self.operation = {'journalRoot': str(self.root / 'installer'), 'release': str(self.bundle),
                          'operationId': 'synthetic-operation'}
        self.selected = {self.image: sorted(['root', *[v[1] for v in M.IDENTITIES.values()]])}
        domains = []
        for index, (domain, (uid, user)) in enumerate(M.IDENTITIES.items()):
            domains.append({'name': domain, 'user': user, 'uid': uid,
                            'graphRoot': str(self.scope / domain), 'subuidStart': 200000 + index * 65536})
        metadata = {'domains': domains, 'deploymentMode': 'standalone'}
        manifest = {'site': 'synthetic', 'deploymentMode': 'standalone',
                    'storageScope': {'root': str(self.scope), 'dataClass': 'synthetic'}}
        services = {'root-consumer': {'image': self.image, 'placement': 'rootful', 'updatePolicy': 'pinned'}}
        for row in domains:
            services[row['name']] = {'image': self.image, 'placement': 'rootless',
                                      'rootlessDomain': row['name'], 'updatePolicy': 'pinned'}
        ir = {'modules': [], 'services': services}
        write_json(self.bundle / 'site/manifest.json', manifest)
        write_json(self.bundle / 'stack.ir.json', ir)
        write_json(self.bundle / 'podman-domains.json', metadata)
        write_json(self.bundle / 'source-provenance.json', {'generatorDirty': False, 'siteDirty': False,
            'generatorCommit': 'a' * 40, 'siteCommit': 'b' * 40, 'modules': [],
            'manifestSha256': sha((self.bundle / 'site/manifest.json').read_bytes())})
        write_json(self.bundle / 'bundle.json', {'backend': 'podman', 'deploymentMode': 'standalone',
            'irSha256': sha((self.bundle / 'stack.ir.json').read_bytes()),
            'sourceProvenanceSha256': sha((self.bundle / 'source-provenance.json').read_bytes())})
        # Fixture ownership simulation: only disposable fixture paths; all opens,
        # links, inode CAS, hashes and real verify_oci remain production behavior.
        self.patches = contextlib.ExitStack(); self.addCleanup(self.patches.close)
        self.patches.enter_context(patch.object(M.os, 'geteuid', return_value=0))
        self.patches.enter_context(patch.object(M.os, 'fchown', return_value=None))
        self.patches.enter_context(patch.object(M, 'floor_reserves'))
        self.patches.enter_context(patch.object(M, 'workspace_parent_check', side_effect=lambda path, fd: None))
        def fixture_protected(fd, **kwargs):
            info = os.fstat(fd)
            require_dir = kwargs.get('directory', False)
            if require_dir:
                self.assertTrue(stat.S_ISDIR(info.st_mode))
            else:
                M.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                          and not info.st_mode & 0o022, 'fixture owner/type/link mode')
        self.patches.enter_context(patch.object(M, 'protected', side_effect=fixture_protected))
        def plain(path, private=False):
            path = Path(path)
            assert path.is_relative_to(self.root)
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1: raise M.Refused('fixture file links')
            return path
        self.patches.enter_context(patch.object(M.package, 'plain_file', side_effect=plain))
        self.patches.enter_context(patch.object(M.package, 'owned_directory', side_effect=Path))
        self.binding, _, _ = M.package.bundle_selection(self.bundle)
        self.marker = {'synthetic': 'exact storage marker'}
        scope_hash = write_json(self.scope / '.stack-installation.json', self.marker)
        self.sources = []
        for index, (domain, (uid, user)) in enumerate([*M.IDENTITIES.items(), ('rootful', (0, 'root'))]):
            graph = self.scope / domain; graph.mkdir(mode=0o700)
            row = {'authority': user, 'domain': domain, 'uid': uid, 'gid': uid,
                   'subuidStart': 200000 + index * 65536 if uid else 0,
                   'subgidStart': 200000 + index * 65536 if uid else 0,
                   'subidCount': 65536 if uid else 0, 'graphRoot': str(graph),
                   'driver': 'overlay', 'storageOptions': [], 'images': [self.image]}
            row['namespace'] = {'uidMap': [[0, uid, 1], [1, row['subuidStart'], 65536]],
                                'gidMap': [[0, uid, 1], [1, row['subgidStart'], 65536]]} if uid else {
                                    'uidMap': [[0, 0, 4294967295]], 'gidMap': [[0, 0, 4294967295]]}
            row['markerSha256'] = write_json(graph / '.selected-image-source.json', {
                'schemaVersion': 1, 'purpose': 'selected-image-source', 'binding': self.binding,
                'operation': self.operation, 'authority': user, 'graphRoot': str(graph)})
            row['inventories'] = {}
            for name, body in (('overlay-images/images.json', [{'id': self.image[7:]}, {'id': 'f' * 64, 'names': ['foreign-base-preserved']}]),
                               ('overlay-layers/layers.json', [{'id': 'unselected-base-layer'}]),
                               ('overlay-containers/containers.json', [])):
                row['inventories'][name] = write_json(graph / name, body)
                (graph / name).parent.chmod(0o700)
            self.sources.append(row)
        self.receipt = {'schemaVersion': 1, 'purpose': 'selected-actor-image-export',
                        'binding': self.binding, 'imageAuthorities': self.selected, 'operation': self.operation,
                        'scope': str(self.scope), 'scopeMarkerSha256': scope_hash,
                        'allocationSha256': {'subuid': '1' * 64, 'subgid': '2' * 64}, 'sources': self.sources}
        self.operator = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        self.storage = SimpleNamespace(MARKER='.stack-installation.json',
            authority=Mock(return_value=(self.scope, self.operator, self.marker)),
            marker=Mock(), safe_parent=Mock())
        self.lease = Lease(self)

    def run_export(self, **kwargs):
        reviewed = write_json(self.receipt_path, self.receipt)
        return M.export_selected(self.bundle, self.receipt_path, reviewed, self.output,
                                 lease=self.lease, storage=self.storage, **kwargs)

    def assert_pending(self):
        self.assertTrue((self.output / 'PENDING').exists())
        self.assertFalse((self.output / 'supply.json').exists())
        self.assertFalse(self.lease.alive)

    def test_real_oci_each_shared_authority_and_packager_supply_api(self):
        before = {str(path): path.read_bytes() for path in self.scope.rglob('*') if path.is_file()}
        result = self.run_export()
        self.assertFalse((self.output / 'PENDING').exists())
        self.assertEqual(len(self.lease.plans), 8)
        self.assertEqual(len(self.lease.exited), 8)
        self.assertFalse(self.lease.alive)
        self.assertGreater(self.lease.lease_calls, 8)
        supply = json.loads(Path(result['supply']).read_bytes())
        rows, proof = M.package.supply_rows(Path(result['supply']), result['supplySha256'], self.binding, self.selected)
        self.assertEqual(set(rows), {self.image})
        self.assertEqual(len(supply['images']), 1)
        export_proof = json.loads(Path(result['proof']).read_bytes())
        self.assertEqual(len(export_proof['evidence']), 8)
        self.assertEqual(export_proof['acceptedIntegratedInstalls'], 0)
        self.assertFalse(export_proof['activationAuthorized'])
        self.assertEqual(export_proof['sourceCustody'][str(self.scope)]['inode'], self.scope.stat().st_ino)
        self.assertTrue(export_proof['sameSourceCAS'])
        for row in export_proof['evidence']:
            self.assertEqual(row['oci']['configId'], self.image)
            self.assertTrue(row['oci']['diffIds'])
            self.assertEqual(stat.S_IMODE((self.output / row['archiveFilename']).stat().st_mode), 0o400)
        self.assertEqual(before, {str(path): path.read_bytes() for path in self.scope.rglob('*') if path.is_file()})
        self.assertEqual(sha(Path(result['proof']).read_bytes()), result['proofSha256'])

    def test_cli_description_is_read_only_and_has_no_authorization_or_executor_flag(self):
        output = io.StringIO()
        with patch('sys.argv', ['export-selected-images.py', '--bundle', str(self.bundle), '--describe-selection']), \
                contextlib.redirect_stdout(output):
            self.assertEqual(M.main(), 0)
        document = json.loads(output.getvalue())
        self.assertEqual(document['imageAuthorities'], self.selected)
        self.assertEqual(document['acceptedIntegratedInstalls'], 0)
        self.assertFalse(self.output.exists()); self.assertFalse(self.lease.plans)
        with patch('sys.argv', ['export-selected-images.py', '--bundle', str(self.bundle),
                               '--describe-selection', '--operation-authorized']), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            M.main()

    def test_explicit_source_only_buildah_plan_no_manager_api_or_environment(self):
        self.run_export()
        for plan in self.lease.plans:
            self.assertEqual(plan['command'][0], '/usr/bin/buildah')
            self.assertEqual(plan['command'][-2], self.image)
            self.assertIn('--root', plan['command']); self.assertIn('--runroot', plan['command'])
            self.assertIn('--storage-driver', plan['command'])
            self.assertNotIn('DBUS_SESSION_BUS_ADDRESS', plan['environment'])
            self.assertNotIn('CONTAINER_HOST', plan['environment'])
            self.assertNotIn('XDG_DATA_HOME', plan['environment'])
            self.assertEqual(plan['supplementaryGroups'], [])
            self.assertEqual(plan['networkPolicy'], 'deny-all')
            self.assertEqual(plan['namespacePrefix'][-1:] if plan['uid'] else [], ['unshare'] if plan['uid'] else [])
            for key in ('XDG_RUNTIME_DIR', 'TMPDIR', 'HOME'):
                self.assertTrue(Path(plan['environment'][key]).is_relative_to(Path(plan['workspace'])))
            config = Path(plan['environment']['CONTAINERS_STORAGE_CONF']).read_text()
            self.assertIn('additionalimagestores = []', config)
            self.assertIn('graphroot = ' + json.dumps(plan['graphRoot']), config)
            self.assertEqual(json.loads(Path(plan['environment']['REGISTRY_AUTH_FILE']).read_text()), {'auths': {}})
            words = ' '.join(plan['command'] + plan['namespacePrefix'])
            for forbidden in ('podman', 'systemctl', 'prune', 'chown', 'login', 'linger', '--rm'):
                self.assertNotIn(forbidden, words)

    def test_no_json_boolean_or_missing_lease_can_authorize(self):
        with self.assertRaisesRegex(M.Refused, 'trusted stopped lease'):
            M.export_selected(self.bundle, self.receipt_path, 'a' * 64, self.output, lease={'approved': True})
        self.lease.verify_export = Mock(return_value={'approved': True})
        with self.assertRaisesRegex(M.Refused, 'None'): self.run_export()
        self.assertFalse(self.output.exists()); self.assertFalse(self.lease.plans)

    def test_wrong_binding_graph_namespace_ranges_scope_refused_before_source_access(self):
        mutations = [lambda: self.receipt['binding'].update(bundleIrSha256='0' * 64),
                     lambda: self.sources[0].update(graphRoot=str(self.scope / 'wrong')),
                     lambda: self.sources[0]['namespace']['uidMap'][1].__setitem__(1, 1),
                     lambda: self.sources[1].update(subgidStart=self.sources[0]['subgidStart']),
                     lambda: self.sources[1].update(uid=1000),
                     lambda: self.sources[0].update(subidCount=65535),
                     lambda: self.receipt.update(scope='/var/lib/containers/storage')]
        original = json.loads(json.dumps(self.receipt))
        for mutate in mutations:
            self.receipt = json.loads(json.dumps(original)); self.sources = self.receipt['sources']
            mutate()
            opened = []
            real = M.Pins.document
            def observe(pins, path, **kwargs):
                opened.append(path)
                return real(pins, path, **kwargs)
            with self.subTest(mutation=mutate), patch.object(M.Pins, 'document', observe), \
                    self.assertRaises((M.Refused, ValueError)):
                self.run_export()
            self.assertEqual(opened, [self.receipt_path])
            self.assertFalse(self.output.exists()); self.assertFalse(self.lease.plans)
        self.storage.authority.assert_not_called()

    def test_manager_api_linger_operation_foreign_allocations_and_writers_refused(self):
        for failure in ('manager', 'operation', 'foreign-range', 'foreign-writer', 'storage-lease', 'reserves'):
            self.lease.fail = failure
            with self.subTest(failure=failure), self.assertRaises(M.Refused): self.run_export()
            self.assertFalse(self.output.exists()); self.assertFalse(self.lease.plans)

    def test_wrong_source_marker_inventory_and_missing_selected_id(self):
        row = self.sources[0]; graph = Path(row['graphRoot'])
        marker = graph / '.selected-image-source.json'; original_marker = marker.read_bytes()
        marker.write_bytes(b'{}')
        with self.assertRaisesRegex(M.Refused, 'marker'): self.run_export()
        marker.write_bytes(original_marker)
        inv = graph / 'overlay-images/images.json'; original = inv.read_bytes()
        inv.write_bytes(M.json_bytes([{'id': 'f' * 64}]))
        with self.assertRaisesRegex(M.Refused, 'inventory CAS'): self.run_export()
        row['inventories']['overlay-images/images.json'] = sha(inv.read_bytes())
        with self.assertRaisesRegex(M.Refused, 'image absent'): self.run_export()
        inv.write_bytes(original)
        self.assertFalse(self.lease.plans); self.assertFalse(self.output.exists())

    def test_actual_wrong_config_archive_refused_not_mocked_verifier(self):
        self.lease.fail = 'wrong-image'
        with self.assertRaisesRegex(ValueError, 'configuration ID'): self.run_export()
        self.assert_pending(); self.assertEqual(len(self.lease.exited), 1)

    def test_shared_image_must_be_exported_and_verified_in_each_source(self):
        self.lease.mutate = lambda: setattr(self.lease, 'fail', 'wrong-image') if len(self.lease.plans) == 1 else None
        with self.assertRaisesRegex(ValueError, 'configuration ID'): self.run_export()
        self.assertEqual(len(self.lease.plans), 2); self.assert_pending()

    def test_backend_mapping_unknown_never_uses_protected_fallback(self):
        self.lease.namespace_bad = True
        with self.assertRaisesRegex(M.Refused, 'namespace compatibility'): self.run_export()
        self.assert_pending(); self.assertEqual(len(self.lease.plans), 1)
        self.assertFalse(Path(self.lease.plans[0]['archive']).exists())

    def test_mismatched_observed_graph_or_namespace_never_pushes(self):
        self.lease.probe_mutate = lambda proof: proof.update(graphRoot='/var/lib/containers/storage')
        with self.assertRaisesRegex(M.Refused, 'probe mismatch'): self.run_export()
        self.assert_pending()
        self.assertFalse(Path(self.lease.plans[0]['archive']).exists())

    def test_review_hash_and_pending_receipt_are_not_self_authorization(self):
        reviewed = write_json(self.receipt_path, self.receipt)
        with self.assertRaisesRegex(M.Refused, 'review hash'):
            M.export_selected(self.bundle, self.receipt_path, '0' * 64, self.output,
                              lease=self.lease, storage=self.storage)
        self.storage.authority.assert_not_called()
        self.assertFalse(self.output.exists()); self.assertFalse(self.lease.plans)
        self.assertNotEqual(reviewed, '0' * 64)

    def test_retained_containers_refused_without_any_prune(self):
        row = self.sources[0]
        inventory = Path(row['graphRoot']) / 'overlay-containers/containers.json'
        row['inventories']['overlay-containers/containers.json'] = write_json(inventory, [{'id': 'preserve-owned-build-cache'}])
        with self.assertRaisesRegex(M.Refused, 'retained storage containers'): self.run_export()
        self.assertIn(b'preserve-owned-build-cache', inventory.read_bytes())
        self.assertFalse(self.output.exists()); self.assertFalse(self.lease.plans)

    def test_source_inventory_cas_drift_preserves_pending_and_foreign_cache(self):
        foreign = Path(self.sources[-1]['graphRoot']) / 'overlay-images/images.json'
        self.lease.mutate = lambda: foreign.write_bytes(foreign.read_bytes() + b' ')
        with self.assertRaisesRegex(M.Refused, 'CAS'): self.run_export()
        self.assert_pending(); self.assertIn(b'foreign-base-preserved', foreign.read_bytes())

    def test_prior_root_copy_cas_drift_refuses_publication(self):
        def tamper():
            if len(self.lease.plans) == 2:
                copied = next(self.output.glob('*.tar'))
                copied.chmod(0o600)
                copied.write_bytes(copied.read_bytes() + b'\0')
        self.lease.mutate = tamper
        with self.assertRaisesRegex(ValueError, 'CAS'): self.run_export()
        self.assert_pending()

    def test_unselected_file_in_output_is_never_a_supply(self):
        self.lease.mutate = lambda: (self.output / 'unexpected-state').write_bytes(b'not-an-image')
        with self.assertRaisesRegex(M.Refused, 'unselected output'): self.run_export()
        self.assert_pending()

    def test_interrupt_partial_growth_lost_lease_and_pause_cleanup_fail_closed(self):
        # Each scenario needs a fresh output; failed children are never resumed.
        for index, failure in enumerate(('interrupt', 'partial', 'lease-after-spawn', 'leaked-pause')):
            self.output = self.root / ('failed-' + str(index)); self.lease = Lease(self); self.lease.fail = failure
            with self.subTest(failure=failure), self.assertRaises((M.Refused, InterruptedError)):
                self.run_export(max_archive_bytes=self.archive.stat().st_size + 100,
                                max_total_bytes=20 * self.archive.stat().st_size)
            self.assertTrue((self.output / 'PENDING').exists())
            self.assertFalse((self.output / 'supply.json').exists())
            self.assertEqual(len(self.lease.exited), 1)
            if failure != 'leaked-pause': self.assertFalse(self.lease.alive)

    def test_existing_output_or_workspace_never_adopted(self):
        self.output.mkdir(); (self.output / 'sentinel').write_bytes(b'preserve')
        with self.assertRaises(FileExistsError): self.run_export()
        self.assertEqual((self.output / 'sentinel').read_bytes(), b'preserve')
        self.output = self.root / 'other-supply'
        work = self.root / 'other-supply.export-work'; work.mkdir()
        with self.assertRaisesRegex(M.Refused, 'new child'): self.run_export()
        self.assertFalse(self.output.exists())

    def test_symlink_hardlink_and_path_escape_source_metadata_refused(self):
        row = self.sources[0]; inv = Path(row['graphRoot']) / 'overlay-images/images.json'
        original = inv.read_bytes(); inv.unlink(); inv.symlink_to(self.archive)
        with self.assertRaises(OSError): self.run_export()
        inv.unlink(); inv.write_bytes(original); alias = self.root / 'alias'; os.link(inv, alias)
        with self.assertRaisesRegex(M.Refused, 'owner/type/link|linked/nonregular'): self.run_export()
        self.assertFalse(self.output.exists()); self.assertFalse(self.lease.plans)
        for path in ('/tmp/../escape', 'relative', '/tmp//ambiguous', '/'):
            with self.assertRaises(M.Refused): M.canonical(path)

    def test_atomic_publication_interruption_retains_pending(self):
        real_rename = M.os.rename
        def fail_rename(src, dst, **kwargs):
            if src == 'export-proof.json.partial': raise InterruptedError('publication cut')
            return real_rename(src, dst, **kwargs)
        with patch.object(M.os, 'rename', side_effect=fail_rename), self.assertRaises(InterruptedError):
            self.run_export()
        self.assertTrue((self.output / 'PENDING').exists())
        self.assertTrue((self.output / 'supply.json').exists())
        self.assertFalse((self.output / 'export-proof.json').exists())
        self.assertFalse(self.lease.alive)


class ProductionGates(unittest.TestCase):
    def test_private_owner_group_mode_type_and_links(self):
        good = dict(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=1)
        for change in ({}, {'st_uid': 1000}, {'st_gid': 1000}, {'st_nlink': 2},
                       {'st_mode': stat.S_IFLNK | 0o777}, {'st_mode': stat.S_IFREG | 0o644}):
            info = SimpleNamespace(**(good | change))
            with patch.object(M.os, 'fstat', return_value=info), patch.object(M, 'acl', return_value=b''):
                if change:
                    with self.assertRaises(M.Refused): M.protected(999, private=True)
                else: M.protected(999, private=True)

    def test_supported_mnt_stack_operator_and_scope_not_all_root_ancestry(self):
        def body(rows):
            return struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *row) for row in rows)
        undefined = 0xffffffff
        base = [(1, 7, undefined), (2, 7, 1000), (4, 7, undefined), (8, 7, 1000),
                (16, 7, undefined), (32, 5, undefined)]
        operator = SimpleNamespace(pw_uid=1000, pw_gid=1000)
        scope = Path('/mnt/stack/selected')
        storage = SimpleNamespace(safe_parent=Mock())
        check = M.source_check(scope, operator, storage, {})
        info = SimpleNamespace(st_uid=1000, st_gid=1000, st_mode=stat.S_IFDIR | 0o2775)
        with patch.object(M.os, 'fstat', return_value=info), patch.object(M, 'acl', return_value=body(base)):
            check(Path('/mnt/stack'), 999)
            storage.safe_parent.assert_not_called()
        for foreign in ((2, 7, 999), (8, 7, 999), (32, 7, undefined)):
            with patch.object(M.os, 'fstat', return_value=info), patch.object(M, 'acl', return_value=body(base + [foreign])):
                with self.assertRaises(M.Refused): check(Path('/mnt/stack'), 999)
        # A scoped 2770+xACL parent goes through canonical safe_parent, not
        # protected(root-only). Pin path identity around its existing ACL gate.
        scope_info = SimpleNamespace(st_uid=1000, st_gid=1000, st_mode=stat.S_IFDIR | 0o2770,
                                     st_dev=1, st_ino=2, st_nlink=2)
        scope_acl = body([(1, 7, undefined), (2, 1, 780), (4, 7, undefined), (16, 7, undefined), (32, 0, undefined)])
        with patch.object(M.os, 'fstat', return_value=scope_info), \
                patch.object(M, 'acl', side_effect=lambda fd, name: b'' if name.endswith('default') else scope_acl), \
                patch.object(Path, 'lstat', return_value=scope_info), patch.object(M, 'mount_id', return_value=1):
            check(scope, 999)
            storage.safe_parent.assert_called_once_with(scope, operator)

    def test_independent_reserves_memory_root_and_stack(self):
        enough = SimpleNamespace(f_bavail=1000 * M.GIB, f_frsize=1)
        for problem in ('root', 'stack', 'memory', None):
            def fs(path):
                return SimpleNamespace(f_bavail=1, f_frsize=1) if path == {'root': '/', 'stack': '/mnt/stack'}.get(problem) else enough
            body = 'MemAvailable: ' + str(1 if problem == 'memory' else 32 * 1024**2) + ' kB\n'
            with patch.object(M.os, 'statvfs', side_effect=fs), patch('builtins.open', return_value=io.StringIO(body)):
                if problem:
                    with self.assertRaises(M.Refused): M.floor_reserves()
                else: M.floor_reserves()

    def test_nested_source_mount_even_same_device_is_refused(self):
        scope = Path('/mnt/stack/selected')
        operator = SimpleNamespace(pw_uid=1000, pw_gid=1000)
        info = SimpleNamespace(st_uid=1000, st_gid=1000, st_mode=stat.S_IFDIR | 0o2770,
                               st_dev=1, st_ino=2, st_nlink=2)
        storage = SimpleNamespace(safe_parent=Mock())
        check = M.source_check(scope, operator, storage, {})
        with patch.object(M.os, 'fstat', return_value=info), patch.object(Path, 'lstat', return_value=info), \
                patch.object(M, 'acl', return_value=b''), patch.object(M, 'mount_id', side_effect=lambda fd: fd):
            check(scope, 1)
            with self.assertRaisesRegex(M.Refused, 'nested source mount'):
                check(scope / 'graph', 2)

    def test_workspace_needs_root_protected_public_traversal_not_private_installer(self):
        for mode in (0o755, 0o711, 0o700, 0o775):
            info = SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | mode, st_nlink=2)
            with patch.object(M.os, 'fstat', return_value=info), patch.object(M, 'acl', return_value=b''):
                if mode in (0o755, 0o711):
                    M.workspace_parent_check(Path('/root-export'), 999)
                else:
                    with self.assertRaises(M.Refused): M.workspace_parent_check(Path('/root-export'), 999)

    def test_owned_partial_scanner_rejects_symlinks_links_sizes_and_total(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root); fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                (path / 'file').write_bytes(b'abcd')
                self.assertEqual(M.owned_bytes(fd, max_file=4, max_total=4), 4)
                with self.assertRaisesRegex(M.Refused, 'oversized partial'):
                    M.owned_bytes(fd, max_file=3, max_total=8)
                (path / 'second').write_bytes(b'abcd')
                with self.assertRaisesRegex(M.Refused, 'aggregate partial'):
                    M.owned_bytes(fd, max_file=4, max_total=7)
                os.link(path / 'file', path / 'alias')
                with self.assertRaisesRegex(M.Refused, 'linked/nonregular'):
                    M.owned_bytes(fd, max_file=8, max_total=100)
                (path / 'alias').unlink(); (path / 'link').symlink_to('/never-read-outside')
                with self.assertRaisesRegex(M.Refused, 'linked/nonregular'):
                    M.owned_bytes(fd, max_file=8, max_total=100)
            finally: os.close(fd)

    def test_bounded_hash_refuses_before_reading_oversized_source(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'file'; path.write_bytes(b'bounded')
            fd = os.open(path, os.O_RDONLY)
            try:
                with patch.object(M.os, 'pread', side_effect=AssertionError('must not read')):
                    with self.assertRaisesRegex(M.Refused, 'oversized CAS'): M.file_cas(fd, max_bytes=1)
            finally: os.close(fd)

    def test_no_follow_fd_walk_rejects_intermediate_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root); (path / 'real').mkdir(); (path / 'linked').symlink_to(path / 'real')
            pins = M.Pins()
            try:
                with self.assertRaises(OSError): pins.directory(path / 'linked', lambda *args: None)
            finally: pins.close()


if __name__ == '__main__':
    unittest.main()
