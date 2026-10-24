#!/usr/bin/env python3
"""Bounded synthetic OCI/freeze/export tests. No runtime, stores, network or secrets.

Package fixtures substitute ownership checks only inside a disposable temp root;
separate tests exercise the production root-owner/link/ancestor gates directly.
"""
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/package-release-images.py'
SPEC = importlib.util.spec_from_file_location('package_images', SOURCE)
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def root_layer(text):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as layer:
        body = text.encode(); entry = tarfile.TarInfo('usr/share/release-fixture')
        entry.size = len(body); layer.addfile(entry, io.BytesIO(body))
    return stream.getvalue()


def fixture(path, *, extra=None, corrupt=False, duplicate=False, arch='amd64',
            compression=None, rootfs=None, reorder=False, foreign=False,
            media=None, config_bytes=None, two_layers=False, bad_size=False):
    raw_layers = [root_layer('synthetic image content; no application state')]
    if two_layers:
        raw_layers.append(root_layer('second synthetic immutable layer'))
    diff_ids = ['sha256:' + sha(body) for body in raw_layers]
    config = config_bytes or json.dumps({'os': 'linux', 'architecture': arch,
                                       'rootfs': rootfs if rootfs is not None else
                                       {'type': 'layers', 'diff_ids': diff_ids}}).encode()
    def descriptor(body, kind):
        return {'mediaType': M.OCI + kind, 'digest': 'sha256:' + sha(body), 'size': len(body)}
    layers = [gzip.compress(body, mtime=0) if compression else body for body in raw_layers]
    config_desc = descriptor(config, 'config.v1+json')
    layer_desc = [descriptor(body, 'layer.v1.tar' + ('+' + compression if compression else '')) for body in layers]
    if foreign: layer_desc[0]['urls'] = ['https://invalid.example/no-request-permitted']
    if media: layer_desc[0]['mediaType'] = media
    if reorder: layer_desc.reverse()
    if bad_size: layer_desc[0]['size'] += 1
    manifest = json.dumps({'schemaVersion': 2, 'mediaType': M.OCI + 'manifest.v1+json',
                           'config': config_desc, 'layers': layer_desc}).encode()
    manifest_desc = descriptor(manifest, 'manifest.v1+json')
    index = json.dumps({'schemaVersion': 2, 'manifests': [manifest_desc]}).encode()
    rows = {'oci-layout': b'{"imageLayoutVersion":"1.0.0"}', 'index.json': index}
    for body in (config, *layers, manifest): rows['blobs/sha256/' + sha(body)] = body
    if corrupt:
        body = config if corrupt == 'config' else manifest if corrupt == 'manifest' else layers[0]
        rows['blobs/sha256/' + sha(body)] = b'X' * len(body)
    if extra: rows.update(extra)
    with tarfile.open(path, 'w') as archive:
        for name, body in rows.items():
            entry = tarfile.TarInfo(name); entry.size = len(body)
            archive.addfile(entry, io.BytesIO(body))
        if duplicate:
            entry = tarfile.TarInfo('index.json'); entry.size = len(index)
            archive.addfile(entry, io.BytesIO(index))
    return config_desc['digest']


class ReleaseImages(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / 'image.tar'

    def test_exact_selected_oci_is_accepted_without_extraction(self):
        for compression in (None, 'gzip'):
            image = fixture(self.archive, compression=compression, two_layers=True)
            before = set(self.root.iterdir())
            proof = M.verify_oci(self.archive, image)
            self.assertEqual(proof['configId'], image)
            self.assertEqual(len(proof['diffIds']), 2)
            self.assertEqual(set(self.root.iterdir()), before)

    def test_configuration_id_drift_refused(self):
        fixture(self.archive)
        with self.assertRaisesRegex(ValueError, 'configuration ID'):
            M.verify_oci(self.archive, 'sha256:' + '0' * 64)

    def test_corrupt_layer_config_or_manifest_refused_before_interpretation(self):
        for corrupt in (True, 'config', 'manifest'):
            image = fixture(self.archive, corrupt=corrupt)
            with self.assertRaisesRegex(ValueError, 'digest mismatch'): M.verify_oci(self.archive, image)

    def test_rootfs_is_bound_to_actual_uncompressed_content(self):
        cases = [({}, 'count/type'), ({'type': 'wrong', 'diff_ids': []}, 'count/type'),
                 ({'type': 'layers', 'diff_ids': []}, 'count/type'),
                 ({'type': 'layers', 'diff_ids': ['bad']}, 'count/type'),
                 ({'type': 'layers', 'diff_ids': ['sha256:' + '0' * 64]}, 'DiffID mismatch')]
        for compression in (None, 'gzip'):
            for rootfs, message in cases:
                with self.subTest(rootfs=rootfs, compression=compression):
                    image = fixture(self.archive, rootfs=rootfs, compression=compression)
                    with self.assertRaisesRegex(ValueError, message): M.verify_oci(self.archive, image)

    def test_layer_order_is_bound_by_config(self):
        image = fixture(self.archive, two_layers=True, reorder=True)
        with self.assertRaisesRegex(ValueError, 'DiffID mismatch'): M.verify_oci(self.archive, image)

    def test_foreign_unknown_zstd_and_wrong_size_fail_closed(self):
        for options in ({'foreign': True}, {'media': 'application/octet-stream'},
                        {'compression': 'zstd'}, {'bad_size': True}):
            with self.subTest(options=options):
                image = fixture(self.archive, **options)
                with self.assertRaises(ValueError): M.verify_oci(self.archive, image)

    def test_decompression_limit_is_bounded(self):
        image = fixture(self.archive, compression='gzip')
        with patch.object(M, 'MAX_LAYER', 1), self.assertRaisesRegex(ValueError, 'limit'):
            M.verify_oci(self.archive, image)

    def test_duplicate_json_is_not_a_different_config_interpretation(self):
        image = fixture(self.archive, config_bytes=b'{"os":"linux","os":"linux","architecture":"amd64"}')
        with self.assertRaisesRegex(ValueError, 'duplicate JSON'): M.verify_oci(self.archive, image)

    def test_duplicate_or_escaping_members_refused(self):
        for options in ({'duplicate': True}, {'extra': {'../other': b'fixture'}},
                        {'extra': {'./other': b'fixture'}}, {'extra': {'/other': b'fixture'}}):
            image = fixture(self.archive, **options)
            with self.assertRaisesRegex(ValueError, 'ambiguous|escaping'): M.verify_oci(self.archive, image)

    def test_unselected_content_and_trailing_archive_are_refused(self):
        image = fixture(self.archive, extra={'unrelated-state': b'not an image blob'})
        with self.assertRaisesRegex(ValueError, 'unselected'): M.verify_oci(self.archive, image)
        image = fixture(self.archive)
        with self.archive.open('ab') as target: target.write(b'hidden unrelated state')
        with self.assertRaisesRegex(ValueError, 'trailing'): M.verify_oci(self.archive, image)

    def test_linked_member_refused_without_extraction(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            image = fixture(self.archive)
            with tarfile.open(self.archive, 'a') as archive:
                entry = tarfile.TarInfo('external-link'); entry.type = kind; entry.linkname = '/outside'
                archive.addfile(entry)
            with self.assertRaisesRegex(ValueError, 'linked'): M.verify_oci(self.archive, image)
        self.assertEqual({p.name for p in self.root.iterdir()}, {'image.tar'})

    def test_standard_oci_directories_allowed_but_extended_headers_refused(self):
        image = fixture(self.archive)
        with tarfile.open(self.archive, 'a') as archive:
            for name in ('blobs', 'blobs/sha256'):
                entry = tarfile.TarInfo(name); entry.type = tarfile.DIRTYPE; archive.addfile(entry)
        M.verify_oci(self.archive, image)
        image = fixture(self.archive)
        with tarfile.open(self.archive, 'a', format=tarfile.PAX_FORMAT) as archive:
            entry = tarfile.TarInfo('blobs'); entry.type = tarfile.DIRTYPE
            entry.pax_headers = {'comment': 'not selected image content'}; archive.addfile(entry)
        with self.assertRaisesRegex(ValueError, 'extended'): M.verify_oci(self.archive, image)

    def test_wrong_platform_refused(self):
        image = fixture(self.archive, arch='arm64')
        with self.assertRaisesRegex(ValueError, 'platform'): M.verify_oci(self.archive, image)

    def test_reserve_failure_cancels_only_owned_export_and_never_inherits_secrets(self):
        process = Mock(pid=12345, returncode=None); process.poll.return_value = None
        captured = {}
        def start_owned(*args, **kwargs):
            for key in ('CONTAINERS_STORAGE_CONF', 'CONTAINERS_CONF', 'REGISTRY_AUTH_FILE'):
                captured[key] = Path(kwargs['env'][key]).read_text()
            return process
        with patch.object(M.subprocess, 'Popen', side_effect=start_owned) as start, \
                patch.object(M, 'owned_directory', side_effect=lambda p: Path(p)), \
                patch.object(M, 'check_reserves', side_effect=[None, ValueError('reserve refusal')]), \
                patch.object(M, 'leader_exited', return_value=False), \
                patch.object(M, 'quiesce_export') as cleanup:
            with self.assertRaisesRegex(ValueError, 'reserve refusal'):
                M.export(['buildah', '--root', '/explicit-cache'], 'sha256:' + '0' * 64,
                         self.root / 'pending', self.root, 5, self.root)
        cleanup.assert_called_once_with(process)
        self.assertTrue(start.call_args.kwargs['start_new_session'])
        environment = start.call_args.kwargs['env']
        self.assertEqual(set(environment), {'PATH', 'HOME', 'TMPDIR', 'REGISTRY_AUTH_FILE', 'LANG',
                                            'CONTAINERS_STORAGE_CONF', 'CONTAINERS_CONF'})
        self.assertIn('additionalimagestores = []', captured['CONTAINERS_STORAGE_CONF'])
        self.assertIn('graphroot = "/explicit-cache"', captured['CONTAINERS_STORAGE_CONF'])
        self.assertEqual(captured['REGISTRY_AUTH_FILE'], '{"auths":{}}\n')
        for key in captured:
            self.assertFalse(Path(environment[key]).exists())
        command = start.call_args.args[0]
        self.assertEqual(command[-1], 'oci-archive:' + str(self.root / 'pending'))
        self.assertNotIn('--rm', command)
        self.assertEqual(command[-2], 'sha256:' + '0' * 64)

    def test_export_deadline_cancels_only_owned_process_group(self):
        process = Mock(pid=45678, returncode=None); process.poll.return_value = None
        with patch.object(M.subprocess, 'Popen', return_value=process), \
                patch.object(M, 'owned_directory', side_effect=lambda p: Path(p)), \
                patch.object(M, 'check_reserves'), patch.object(M.time, 'monotonic', side_effect=[0, 2]), \
                patch.object(M, 'leader_exited', return_value=False), \
                patch.object(M, 'quiesce_export') as cleanup:
            with self.assertRaisesRegex(ValueError, 'deadline'):
                M.export(['buildah', '--root', '/explicit-cache'], 'sha256:' + '0' * 64,
                         self.root / 'pending', self.root, 1, self.root)
        cleanup.assert_called_once_with(process)

    def test_early_reserve_and_partial_limits_precede_spawn_and_hash(self):
        for kind in ('reserve', 'oversize', 'link', 'hardlink'):
            archive = self.root / 'partial'
            if kind == 'oversize': archive.write_bytes(b'oversized')
            if kind == 'link': archive.symlink_to(self.archive)
            if kind == 'hardlink':
                self.archive.write_bytes(b'x'); os.link(self.archive, archive)
            def protected(path):
                path = Path(path); info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError('linked partial')
                return path
            with patch.object(M, 'owned_directory', side_effect=Path), \
                    patch.object(M, 'plain_file', side_effect=protected), \
                    patch.object(M, 'MAX_ARCHIVE', 1), \
                    patch.object(M, 'check_reserves', side_effect=ValueError('reserve') if kind == 'reserve' else None), \
                    patch.object(M.subprocess, 'Popen') as start, \
                    patch.object(M, 'digest_file', side_effect=AssertionError('must not hash partial')):
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    M.export(['buildah', '--root', '/explicit-cache'], 'sha256:' + '0' * 64,
                             archive, self.root, 1, self.root)
                start.assert_not_called()
            if os.path.lexists(archive): archive.unlink()
            self.assertFalse(list(self.root.glob('release-export-*')))

    def test_oversized_live_partial_cancels_even_after_leader_exit(self):
        for exited in (False, True):
            process = Mock(pid=98765, returncode=0)
            archive = self.root / 'partial'
            def start(*args, **kwargs):
                archive.write_bytes(b'oversized')
                return process
            with patch.object(M, 'owned_directory', side_effect=Path), \
                    patch.object(M, 'plain_file', side_effect=Path), patch.object(M, 'MAX_ARCHIVE', 1), \
                    patch.object(M, 'check_reserves'), patch.object(M.subprocess, 'Popen', side_effect=start), \
                    patch.object(M, 'leader_exited', return_value=exited), \
                    patch.object(M, 'quiesce_export') as cleanup, \
                    patch.object(M, 'digest_file', side_effect=AssertionError('must not hash partial')):
                with self.subTest(exited=exited), self.assertRaisesRegex(ValueError, 'oversized partial'):
                    M.export(['buildah', '--root', '/explicit-cache'], 'sha256:' + '0' * 64,
                             archive, self.root, 1, self.root)
                cleanup.assert_called_once_with(process)
            archive.unlink()

    def test_real_owned_descendants_die_independently_of_leader_and_repeated_interrupts(self):
        # Each wrapper is its own Linux subreaper. Only its synthetic children
        # receive signals; no runtime executable, store, service or app is used.
        for scenario in ('term-leader', 'exited-leader', 'ignoring-leader', 'interrupts'):
            directory = self.root / scenario; directory.mkdir()
            result = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                     '--owned-process-fixture', scenario, str(directory)],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=15, check=False,
                                    env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                                         'PYTHONDONTWRITEBYTECODE': '1'})
            self.assertEqual(result.returncode, 0, (scenario, result.stderr.decode()))
            self.assertEqual(json.loads(result.stdout), {'groupGone': True, 'childReaped': True,
                                                        'configsRemoved': True, 'writerStopped': True})

    def test_group_quiescence_failure_is_bounded_and_never_resignals_after_reap(self):
        process = Mock(pid=12345)
        with patch.object(M.os, 'killpg') as kill, patch.object(M, 'group_exists', return_value=True), \
                patch.object(M, 'leader_exited', return_value=True), \
                patch.object(M.time, 'monotonic', side_effect=[0, 6, 6, 12]):
            with self.assertRaisesRegex(ValueError, 'did not quiesce'): M.quiesce_export(process)
        self.assertEqual(kill.call_args_list, [unittest.mock.call(12345, M.signal.SIGTERM),
                                             unittest.mock.call(12345, M.signal.SIGKILL)])
        process.wait.assert_called_once_with(timeout=M.KILL_GRACE)

    def test_lost_waitable_child_identity_never_signals_numeric_group(self):
        process = Mock(pid=12345)
        with patch.object(M, 'leader_exited', side_effect=ChildProcessError('not our waitable child')), \
                patch.object(M.os, 'killpg') as kill:
            with self.assertRaises(ChildProcessError): M.quiesce_export(process)
        kill.assert_not_called()
        process.wait.assert_not_called()

    def test_all_handled_interrupts_defer_through_spawn_and_entire_cleanup(self):
        process = Mock(pid=12345)
        numbers = (M.signal.SIGINT, M.signal.SIGTERM, M.signal.SIGALRM)
        original_handlers = {number: M.signal.getsignal(number) for number in numbers}
        def repeated():
            for number in numbers * 3:
                M.signal.getsignal(number)(number, None)
        def start(*args, **kwargs):
            repeated()
            return process
        def cleanup(owned):
            self.assertIs(owned, process)
            repeated()
            self.assertTrue(list(self.root.glob('release-export-*')))
        with patch.object(M.subprocess, 'Popen', side_effect=start), \
                patch.object(M, 'owned_directory', side_effect=Path), patch.object(M, 'check_reserves'), \
                patch.object(M, 'quiesce_export', side_effect=cleanup) as stop:
            with self.assertRaises(InterruptedError):
                M.export(['buildah', '--root', '/explicit-cache'], 'sha256:' + '0' * 64,
                         self.root / 'pending', self.root, 1, self.root)
        stop.assert_called_once_with(process)
        self.assertFalse(list(self.root.glob('release-export-*')))
        self.assertEqual({number: M.signal.getsignal(number) for number in numbers}, original_handlers)

    def test_export_start_failure_cleans_only_own_transient_configs(self):
        with patch.object(M.subprocess, 'Popen', side_effect=OSError('synthetic exec failure')), \
                patch.object(M, 'owned_directory', side_effect=lambda p: Path(p)), \
                patch.object(M, 'check_reserves'):
            with self.assertRaises(OSError):
                M.export(['buildah', '--root', '/explicit-cache'], 'sha256:' + '0' * 64,
                         self.root / 'pending', self.root, 1, self.root)
        self.assertEqual({p.name for p in self.root.iterdir()}, {'transfer-tmp'})

    def test_production_file_and_directory_gates(self):
        def info(mode=stat.S_IFREG | 0o600, uid=0, links=1):
            return SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=links)
        original = Path.lstat
        leaf = self.root / 'file'
        def mocked(path, **kwargs):
            return info() if path == leaf else info(stat.S_IFDIR | 0o700)
        with patch.object(Path, 'lstat', mocked):
            self.assertEqual(M.plain_file(leaf), leaf)
        for bad in (info(uid=1), info(links=2), info(stat.S_IFLNK | 0o777), info(stat.S_IFREG | 0o622)):
            with patch.object(Path, 'lstat', lambda path, **kw: bad if path == leaf else info(stat.S_IFDIR | 0o700)):
                with self.assertRaises(ValueError): M.plain_file(leaf)
        for bad in (info(stat.S_IFDIR | 0o777), info(stat.S_IFDIR | 0o700, uid=1), info(stat.S_IFLNK | 0o777)):
            with patch.object(Path, 'lstat', lambda path, **kw: info() if path == leaf else bad):
                with self.assertRaises(ValueError): M.plain_file(leaf)
                with self.assertRaises(ValueError): M.owned_directory(self.root)
        self.assertIs(Path.lstat, original)


class FreezeWorkflow(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / 'bundle'; self.bundle.mkdir()
        self.supply = self.root / 'supply'; self.supply.mkdir()
        self.output = self.root / 'release'
        self.image = fixture(self.supply / 'image.tar', compression='gzip')
        self.site = self.bundle / 'site'; self.site.mkdir()
        self.json(self.site / 'manifest.json', {'localBuildImagePinsPath': 'local-pins.json'})
        self.json(self.site / 'local-pins.json', {'schemaVersion': 1, 'images': {'producer': self.image}})
        self.ir = {'modules': [], 'quadletBuildImagesFrozen': True, 'services': {
            'producer': {'build': {'context': 'synthetic'}, 'image': self.image, 'frozenBuildImage': self.image,
                         'updatePolicy': 'pinned', 'placement': 'rootless', 'rootlessDomain': 'apps'},
            'consumer': {'image': self.image, 'frozenBuildImage': self.image, 'updatePolicy': 'pinned',
                         'placement': 'rootless', 'rootlessDomain': 'workloads'}}}
        self.provenance = {'generatorCommit': '1' * 40, 'generatorDirty': False,
                           'siteCommit': '2' * 40, 'siteDirty': False, 'modules': [],
                           'manifestSha256': M.digest_file(self.site / 'manifest.json')}
        self.json(self.bundle / 'podman-domains.json', {'domains': [{'name': 'apps', 'user': 'release-apps'},
                                                                 {'name': 'workloads', 'user': 'release-workloads'}]})
        self.refresh_bundle()
        # Only root ownership and ancestor ownership are simulated. All actual
        # I/O, hardlink/symlink checks, hashes, CAS, staging and OCI parsing run.
        self.addCleanup(patch.stopall)
        patch.object(M, 'plain_file', side_effect=self.fixture_file).start()
        patch.object(M, 'owned_directory', side_effect=self.fixture_directory).start()
        patch.object(M.os, 'geteuid', return_value=0).start()
        self.reserves = patch.object(M, 'check_reserves').start()
        self.export = patch.object(M, 'export', side_effect=AssertionError('unexpected runtime export')).start()
        self.binding, self.selected, _ = M.bundle_selection(self.bundle)
        self.supply_doc = {'schemaVersion': 1, 'purpose': 'release-image-supply', 'binding': self.binding,
                           'imageAuthorities': self.selected, 'images': [{
                               'image': self.image, 'archiveFilename': 'image.tar',
                               'archiveSha256': M.digest_file(self.supply / 'image.tar'),
                               'archiveBytes': (self.supply / 'image.tar').stat().st_size}]}
        self.supply_path = self.supply / 'supply.json'; self.json(self.supply_path, self.supply_doc)

    def fixture_file(self, path, private=False):
        path = Path(path)
        self.assertTrue(path.is_absolute() and '..' not in path.parts)
        self.assertTrue(path.is_relative_to(self.root))
        for item in (path, *list(path.parents)[:len(path.relative_to(self.root).parts)]):
            if item.is_symlink(): raise ValueError('linked fixture input')
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022:
            raise ValueError('fixture is not protected unlinked regular file')
        return path

    def fixture_directory(self, path):
        path = Path(path)
        if not path.is_absolute() or '..' in path.parts or not path.is_relative_to(self.root):
            raise ValueError('fixture authority escapes')
        for item in (path, *list(path.parents)[:len(path.relative_to(self.root).parts)]):
            if item.is_symlink(): raise ValueError('linked fixture authority')
        if not path.is_dir(): raise ValueError('fixture directory missing')
        return path

    def json(self, path, body):
        path.write_text(json.dumps(body))

    def refresh_bundle(self):
        self.json(self.bundle / 'stack.ir.json', self.ir)
        self.json(self.bundle / 'source-provenance.json', self.provenance)
        self.json(self.bundle / 'bundle.json', {'backend': 'podman',
                  'irSha256': M.digest_file(self.bundle / 'stack.ir.json'),
                  'sourceProvenanceSha256': M.digest_file(self.bundle / 'source-provenance.json')})

    def run_package(self, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            M.package(self.bundle, None, None, self.output, 5, supply_inputs=self.supply_path,
                      supply_sha256=M.digest_file(self.supply_path), **kwargs)

    def test_offline_freeze_keeps_ids_and_every_own_store_authority(self):
        self.run_package()
        self.export.assert_not_called()
        self.assertFalse((self.output / 'PENDING').exists())
        inputs = json.loads((self.output / 'image-inputs.json').read_text())
        proof = json.loads((self.output / 'release-image-proof.json').read_text())
        self.assertEqual(inputs['images'][0]['image'], self.image)
        self.assertEqual(inputs['images'][0]['archiveSha256'], self.supply_doc['images'][0]['archiveSha256'])
        self.assertEqual(proof['imageAuthorities'], {self.image: ['release-apps', 'release-workloads']})
        self.assertEqual(proof['binding'], self.binding)
        self.assertEqual(proof['imageInputsSha256'], M.digest_file(self.output / 'image-inputs.json'))
        self.assertEqual(proof['acceptedIntegratedInstalls'], 0)
        self.assertEqual(proof['ociProofs'][self.image]['configId'], self.image)
        self.assertEqual((self.output / inputs['images'][0]['archiveFilename']).stat().st_nlink, 1)
        with self.assertRaisesRegex(ValueError, 'fresh output'): self.run_package()

    def test_wrong_authority_or_source_hash_or_missing_image_refused_before_staging(self):
        for changed in ({'imageAuthorities': {self.image: ['release-apps']}},
                        {'binding': {**self.binding, 'sourceProvenanceSha256': '0' * 64}},
                        {'images': []}, {'schemaVersion': True}):
            self.json(self.supply_path, {**self.supply_doc, **changed})
            with self.assertRaises(ValueError): self.run_package()
            self.assertFalse(self.output.exists())

    def test_archive_corruption_path_escape_and_hardlink_refused(self):
        row = self.supply_doc['images'][0]
        for changed in ({'archiveSha256': '0' * 64}, {'archiveBytes': True}, {'archiveFilename': '../image.tar'}):
            self.json(self.supply_path, {**self.supply_doc, 'images': [{**row, **changed}]})
            with self.assertRaises(ValueError): self.run_package()
            self.assertFalse(self.output.exists())
        self.json(self.supply_path, self.supply_doc)
        os.link(self.supply / 'image.tar', self.supply / 'alias.tar')
        with self.assertRaisesRegex(ValueError, 'unlinked'): self.run_package()
        self.assertFalse(self.output.exists())

    def test_linked_supply_or_output_and_nonroot_operator_refused(self):
        with patch.object(M.os, 'geteuid', return_value=1000):
            with self.assertRaisesRegex(ValueError, 'root packaging'): self.run_package()
        archive = self.supply / 'image.tar'
        archive.rename(self.supply / 'real.tar'); archive.symlink_to(self.supply / 'real.tar')
        with self.assertRaisesRegex(ValueError, 'linked'): self.run_package()
        archive.unlink(); (self.supply / 'real.tar').rename(archive)
        self.output.symlink_to(self.supply, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'fresh output'): self.run_package()
        self.assertEqual(M.digest_file(archive), self.supply_doc['images'][0]['archiveSha256'])

    def test_reserve_failure_retains_pending_and_never_publishes(self):
        def reserve(path):
            if Path(path) == self.output: raise ValueError('synthetic reserve floor')
        self.reserves.side_effect = reserve
        with self.assertRaisesRegex(ValueError, 'reserve floor'): self.run_package()
        self.assertTrue((self.output / 'PENDING').exists())
        self.assertFalse((self.output / 'image-inputs.json').exists())
        self.export.assert_not_called()

    def test_growing_supply_copy_refuses_before_writing_beyond_reviewed_bound(self):
        archive = self.supply / 'image.tar'
        original_open = Path.open
        grown = archive.read_bytes() + b'unreviewed growth'
        def grow_on_copy(path, *args, **kwargs):
            if path == archive and list(self.output.glob('*.oci.partial')):
                return io.BytesIO(grown)
            return original_open(path, *args, **kwargs)
        with patch.object(Path, 'open', grow_on_copy):
            with self.assertRaisesRegex(ValueError, 'oversized partial'): self.run_package()
        self.assertTrue((self.output / 'PENDING').exists())
        self.assertEqual(next(self.output.glob('*.oci.partial')).stat().st_size, 0)
        self.assertFalse((self.output / 'image-inputs.json').exists())
        self.export.assert_not_called()

    def test_metadata_hash_is_external_cas_not_self_assertion(self):
        with self.assertRaisesRegex(ValueError, 'metadata hash'):
            M.supply_rows(self.supply_path, '0' * 64, self.binding, self.selected)

    def test_dirty_unfrozen_or_drifted_source_cannot_freeze(self):
        for kind in ('dirty', 'unfrozen', 'pins', 'consumer'):
            with self.subTest(kind=kind):
                if kind == 'dirty': self.provenance['generatorDirty'] = True
                if kind == 'unfrozen': self.ir['quadletBuildImagesFrozen'] = False
                if kind == 'pins': self.json(self.site / 'local-pins.json', {'schemaVersion': 1, 'images': {}})
                if kind == 'consumer': self.ir['services']['consumer']['frozenBuildImage'] = 'sha256:' + '0' * 64
                self.refresh_bundle()
                with self.assertRaises(ValueError): M.bundle_selection(self.bundle)
                self.provenance['generatorDirty'] = False; self.ir['quadletBuildImagesFrozen'] = True
                self.ir['services']['consumer']['frozenBuildImage'] = self.image
                self.json(self.site / 'local-pins.json', {'schemaVersion': 1, 'images': {'producer': self.image}})
        self.assertFalse(self.output.exists())

    def standalone(self):
        manifest = json.loads((self.site / 'manifest.json').read_text())
        manifest['deploymentMode'] = 'standalone'
        self.json(self.site / 'manifest.json', manifest)
        self.provenance['manifestSha256'] = M.digest_file(self.site / 'manifest.json')
        domains = json.loads((self.bundle / 'podman-domains.json').read_text())
        domains['deploymentMode'] = 'standalone'
        self.json(self.bundle / 'podman-domains.json', domains)
        self.refresh_bundle()
        metadata = json.loads((self.bundle / 'bundle.json').read_text())
        metadata['deploymentMode'] = 'standalone'
        self.json(self.bundle / 'bundle.json', metadata)

    def test_standalone_freeze_covers_all_15_producers_and_new_security_caddy_without_name_allowlist(self):
        # Synthetic recipe names/IDs prove set closure, not a real image build.
        producers = {'producer': self.image}
        for index in range(14):
            name = 'on-demand-producer-' + str(index)
            producers[name] = self.image
            self.ir['services'][name] = {**self.ir['services']['producer'],
                                        'lifecycle': 'on-demand', 'quadletManaged': False}
        for count in (15, 16):
            if count == 16:
                producers['security-caddy'] = self.image
                self.ir['services']['security-caddy'] = {**self.ir['services']['producer'],
                                                         'placement': 'rootful'}
                self.ir['services']['security-caddy'].pop('rootlessDomain')
            self.json(self.site / 'local-pins.json', {'schemaVersion': 1, 'images': producers})
            self.standalone()
            binding, selected, _ = M.bundle_selection(self.bundle)
            self.assertEqual(binding['localBuildPinsSha256'], M.digest_file(self.site / 'local-pins.json'))
            self.assertEqual(selected[self.image], sorted(['release-apps', 'release-workloads'] +
                                                         (['root'] if count == 16 else [])))
            for altered in ({k: v for k, v in producers.items() if k != 'on-demand-producer-0'},
                            {**producers, 'not-selected': self.image},
                            {**producers, 'on-demand-producer-0': 'sha256:' + '0' * 64}):
                self.json(self.site / 'local-pins.json', {'schemaVersion': 1, 'images': altered})
                with self.assertRaisesRegex(ValueError, 'producer pins'): M.bundle_selection(self.bundle)
            self.json(self.site / 'local-pins.json', {'schemaVersion': 1, 'images': producers})
        self.ir['services']['on-demand-producer-0'].pop('frozenBuildImage')
        self.ir['services']['on-demand-producer-0']['image'] = 'localhost/not-frozen:bundle'
        self.standalone()
        with self.assertRaisesRegex(ValueError, 'must be frozen'): M.bundle_selection(self.bundle)

    def test_legacy_profile_keeps_on_demand_unmanaged_build_filter(self):
        self.ir['services']['legacy-task'] = {'build': {'context': 'synthetic'},
                                             'lifecycle': 'on-demand', 'quadletManaged': False,
                                             'image': 'localhost/unmanaged:bundle'}
        self.refresh_bundle()
        binding, selected, _ = M.bundle_selection(self.bundle)
        self.assertEqual(binding, {**self.binding, 'bundleIrSha256': M.digest_file(self.bundle / 'stack.ir.json')})
        self.assertEqual(selected, self.selected)
        self.json(self.site / 'local-pins.json', {'schemaVersion': 1,
                                                'images': {'producer': self.image, 'legacy-task': self.image}})
        with self.assertRaisesRegex(ValueError, 'producer pins'): M.bundle_selection(self.bundle)

    def test_legacy_managed_on_demand_build_still_requires_freeze_pin(self):
        self.ir['services']['managed-task'] = {**self.ir['services']['producer'],
                                              'lifecycle': 'on-demand', 'quadletManaged': True}
        self.refresh_bundle()
        with self.assertRaisesRegex(ValueError, 'producer pins'): M.bundle_selection(self.bundle)
        self.json(self.site / 'local-pins.json', {'schemaVersion': 1,
                                                'images': {'producer': self.image, 'managed-task': self.image}})
        _, selected, _ = M.bundle_selection(self.bundle)
        self.assertEqual(selected, self.selected)

    def test_mixed_standalone_profile_is_refused(self):
        self.standalone()
        metadata = json.loads((self.bundle / 'bundle.json').read_text()); metadata.pop('deploymentMode')
        self.json(self.bundle / 'bundle.json', metadata)
        with self.assertRaisesRegex(ValueError, 'profile differs'): M.bundle_selection(self.bundle)

    def test_interruption_retains_pending_without_installer_manifest(self):
        with patch.object(M, 'verify_oci', side_effect=InterruptedError('synthetic interrupt')):
            with self.assertRaises(InterruptedError): self.run_package()
        self.assertTrue((self.output / 'PENDING').exists())
        self.assertTrue(list(self.output.glob('*.partial')))
        self.assertFalse((self.output / 'image-inputs.json').exists())
        with self.assertRaisesRegex(ValueError, 'fresh output'): self.run_package()

    def test_late_bundle_or_supply_cas_drift_retains_pending(self):
        original = M.verify_oci
        def drift(path, image, guard):
            result = original(path, image, guard)
            self.json(self.supply_path, {**self.supply_doc, 'purpose': 'changed-after-review'})
            return result
        with patch.object(M, 'verify_oci', side_effect=drift):
            with self.assertRaisesRegex(ValueError, 'CAS changed'): self.run_package()
        self.assertTrue((self.output / 'PENDING').exists())
        self.assertFalse((self.output / 'image-inputs.json').exists())

    def test_prior_staged_archive_cas_is_checked_until_manifest_publication(self):
        second = fixture(self.supply / 'second.tar', two_layers=True)
        self.ir['services']['second'] = {'image': second, 'updatePolicy': 'pinned', 'placement': 'rootful'}
        self.refresh_bundle()
        self.binding, self.selected, _ = M.bundle_selection(self.bundle)
        self.supply_doc.update(binding=self.binding, imageAuthorities=self.selected)
        self.supply_doc['images'].append({'image': second, 'archiveFilename': 'second.tar',
                                         'archiveSha256': M.digest_file(self.supply / 'second.tar'),
                                         'archiveBytes': (self.supply / 'second.tar').stat().st_size})
        self.json(self.supply_path, self.supply_doc)
        original = M.verify_oci
        def drift_prior(path, image, guard):
            result = original(path, image, guard)
            for prior in self.output.glob('*.oci.tar'):
                with prior.open('ab') as target: target.write(b'changed after verification')
            return result
        with patch.object(M, 'verify_oci', side_effect=drift_prior):
            with self.assertRaisesRegex(ValueError, 'CAS changed'): self.run_package()
        self.assertTrue((self.output / 'PENDING').exists())
        self.assertFalse((self.output / 'image-inputs.json').exists())

    def cache(self):
        store = self.root / 'cache'; store.mkdir()
        runroot = self.root / 'run'; runroot.mkdir()
        (store / 'overlay-images').mkdir()
        self.json(store / 'overlay-images/images.json', [{'id': self.image[7:]}])
        marker = store / '.release-image-source.json'
        self.json(marker, {'schemaVersion': 1, 'purpose': 'selected-release-export-cache', 'graphRoot': str(store)})
        receipt = self.root / 'export-config' / 'receipt.json'; receipt.parent.mkdir()
        body = {'schemaVersion': 1, 'purpose': 'release-image-export', 'binding': self.binding,
                'imageAuthorities': self.selected, 'graphRoot': str(store), 'runRoot': str(runroot),
                'sourceMarkerSha256': M.digest_file(marker),
                'inventorySha256': M.digest_file(store / 'overlay-images/images.json')}
        self.json(receipt, body)
        return store, runroot, receipt, body

    def test_export_cache_requires_marker_receipt_and_exact_selected_inventory(self):
        store, runroot, receipt, body = self.cache()
        M.cache_source(store, runroot, receipt, M.digest_file(receipt), self.binding, self.selected)
        inventory = store / 'overlay-images/images.json'
        self.json(inventory, [{'id': self.image[7:]}, {'id': '0' * 64}])
        body['inventorySha256'] = M.digest_file(inventory); self.json(receipt, body)
        with self.assertRaisesRegex(ValueError, 'exactly selected'):
            M.cache_source(store, runroot, receipt, M.digest_file(receipt), self.binding, self.selected)
        (store / '.release-image-source.json').unlink()
        with self.assertRaises(OSError):
            M.cache_source(store, runroot, receipt, M.digest_file(receipt), self.binding, self.selected)
        self.export.assert_not_called()

    def test_wrong_scope_receipts_never_touch_inventory_or_export(self):
        store, runroot, receipt, body = self.cache()
        inventory = store / 'overlay-images/images.json'
        changes = ({'schemaVersion': True}, {'purpose': 'other'},
                   {'binding': {**self.binding, 'bundleIrSha256': '0' * 64}},
                   {'imageAuthorities': {self.image: ['root']}}, {'graphRoot': str(self.root / 'other')},
                   {'runRoot': str(self.root / 'other-run')}, {'sourceMarkerSha256': '0' * 64},
                   {'inventorySha256': 'invalid'}, {'unexpected': True})
        originals = {name: getattr(Path, name) for name in ('stat', 'lstat', 'open')}
        for changed in changes:
            self.json(receipt, {**body, **changed})
            def spy(name):
                def inspect(path, *args, **kwargs):
                    if path == inventory: raise AssertionError('wrong scope touched inventory: ' + name)
                    return originals[name](path, *args, **kwargs)
                return inspect
            with self.subTest(changed=changed), contextlib.ExitStack() as stack:
                for name in originals: stack.enter_context(patch.object(Path, name, spy(name)))
                with self.assertRaisesRegex(ValueError, 'scope/marker/source'):
                    M.package(self.bundle, store, runroot, self.output, 5,
                              source_receipt=receipt, source_receipt_sha256=M.digest_file(receipt))
                self.export.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_oversized_inventory_and_supply_are_refused_before_hash(self):
        store, runroot, receipt, _ = self.cache()
        inventory = store / 'overlay-images/images.json'
        original = M.snapshot
        def no_inventory_hash(path):
            if Path(path) == inventory: raise AssertionError('oversized inventory was hashed')
            return original(path)
        # Keep receipt/marker metadata below the limit while inventory is larger.
        inventory.write_text(' ' * 4096)
        with patch.object(M, 'MAX_METADATA', 2048), patch.object(M, 'snapshot', side_effect=no_inventory_hash):
            with self.assertRaisesRegex(ValueError, 'oversized source inventory'):
                M.cache_source(store, runroot, receipt, M.digest_file(receipt), self.binding, self.selected)
        archive = self.supply / 'image.tar'
        with archive.open('ab') as target: target.write(b'changed-size')
        def no_archive_hash(path):
            if Path(path) == archive: raise AssertionError('wrong-size supply was hashed')
            return original(path)
        with patch.object(M, 'snapshot', side_effect=no_archive_hash):
            with self.assertRaisesRegex(ValueError, 'size/hash'): self.run_package()
        self.export.assert_not_called()

    def test_protected_cache_refusal_precedes_any_filesystem_inspection(self):
        for name in ('/var/lib/containers/storage', '/var/lib/containers/storage/nested',
                     '/private/software_lab/cache', '/private/stack_lab/cache', '/private/obelisks/cache'):
            with patch.object(M, 'owned_directory', side_effect=AssertionError('protected path inspected')):
                with self.assertRaisesRegex(ValueError, 'protected/default'):
                    M.cache_source(name, '/unused', '/unused', '0' * 64, self.binding, self.selected)

    def test_cache_export_is_immutable_id_only_and_retains_source_inventory(self):
        store, runroot, receipt, _ = self.cache()
        before = M.digest_file(store / 'overlay-images/images.json')
        def synthetic_export(command, image, archive, root, seconds, run):
            self.assertEqual(image, self.image)
            self.assertEqual(command, ['buildah', '--root', str(store), '--runroot', str(runroot), '--storage-driver', 'overlay'])
            shutil.copyfile(self.supply / 'image.tar', archive)
        self.export.side_effect = synthetic_export
        with contextlib.redirect_stdout(io.StringIO()):
            M.package(self.bundle, store, runroot, self.output, 5,
                      source_receipt=receipt, source_receipt_sha256=M.digest_file(receipt))
        self.assertEqual(M.digest_file(store / 'overlay-images/images.json'), before)
        self.assertEqual(self.export.call_count, 1)
        self.assertFalse((self.output / 'PENDING').exists())

    def test_reused_runroot_and_overlapping_output_are_refused(self):
        store, runroot, receipt, _ = self.cache()
        (runroot / 'unrelated').write_text('must not mutate')
        with self.assertRaisesRegex(ValueError, 'fresh dedicated empty'):
            M.cache_source(store, runroot, receipt, M.digest_file(receipt), self.binding, self.selected)
        self.output = self.supply / 'release'
        with self.assertRaisesRegex(ValueError, 'disjoint'): self.run_package()
        self.assertFalse(self.output.exists())
        self.assertEqual((runroot / 'unrelated').read_text(), 'must not mutate')

    def test_cache_inventory_drift_during_mock_export_prevents_publication(self):
        store, runroot, receipt, _ = self.cache()
        def drift(command, image, archive, root, seconds, run):
            shutil.copyfile(self.supply / 'image.tar', archive)
            self.json(store / 'overlay-images/images.json', [])
        self.export.side_effect = drift
        with self.assertRaisesRegex(ValueError, 'CAS changed'):
            M.package(self.bundle, store, runroot, self.output, 5,
                      source_receipt=receipt, source_receipt_sha256=M.digest_file(receipt))
        self.assertTrue((self.output / 'PENDING').exists())
        self.assertFalse((self.output / 'image-inputs.json').exists())


def owned_process_fixture(scenario, root):
    """Disposable Linux subreaper; all process control stays inside this fixture."""
    import ctypes
    import signal
    import threading
    import time
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise RuntimeError('isolated subreaper unavailable')
    root = Path(root)
    pidfile = root / 'child-pid'; heartbeat = root / 'heartbeat'
    child_code = '''
import os, signal, sys, time
from pathlib import Path
root = Path(sys.argv[1])
child = os.fork()
if child == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    (root / 'child-pid.partial').write_text(str(os.getpid()))
    (root / 'child-pid.partial').replace(root / 'child-pid')
    while True:
        with (root / 'heartbeat').open('ab') as target: target.write(b'x')
        time.sleep(.01)
def termed(signum, frame):
    (root / 'leader-termed').write_text('TERM received')
    os._exit(0)
signal.signal(signal.SIGTERM, termed)
while not (root / 'child-pid').exists(): time.sleep(.005)
if sys.argv[2] == 'exited-leader': os._exit(0)
if sys.argv[2] == 'ignoring-leader': signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True: time.sleep(.01)
'''
    real_start = subprocess.Popen
    owned = []; reaped = []; thread_errors = []
    def start(*args, **kwargs):
        process = real_start([sys.executable, '-c', child_code, str(root), scenario], **kwargs)
        owned.append(process)
        return process
    def interrupt(signum, frame): raise InterruptedError('isolated cancellation')
    signal.signal(signal.SIGINT, interrupt)
    def monitor():
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGALRM})
        try:
            deadline = time.monotonic() + 10
            while not pidfile.exists():
                if time.monotonic() > deadline: raise AssertionError('child did not start')
                time.sleep(.005)
            child = int(pidfile.read_text())
            if scenario == 'interrupts':
                time.sleep(.1)
                for _ in range(5):
                    os.kill(os.getpid(), signal.SIGINT); time.sleep(.04)
            while time.monotonic() < deadline:
                try:
                    result, status = os.waitpid(child, os.WNOHANG)
                    if result == child:
                        assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
                        reaped.append(child); return
                except ChildProcessError:
                    pass  # Not orphaned/reparented to this subreaper yet.
                time.sleep(.005)
            raise AssertionError('owned descendant was not reaped')
        except BaseException as error:
            thread_errors.append(error)
    thread = threading.Thread(target=monitor); thread.start()
    def reserve(path):
        if pidfile.exists() and scenario not in ('exited-leader', 'interrupts'):
            raise ValueError('isolated reserve cancellation')
    try:
        with patch.object(M.subprocess, 'Popen', side_effect=start), \
                patch.object(M, 'owned_directory', side_effect=Path), \
                patch.object(M, 'check_reserves', side_effect=reserve), \
                patch.object(M, 'TERM_GRACE', .35), patch.object(M, 'KILL_GRACE', 2), \
                patch.object(M, 'GROUP_POLL', .01):
            try:
                M.export(['fixture-only', '--root', str(root / 'never-opened-graph')],
                         'sha256:' + '0' * 64, root / 'partial', root, 3, root)
                assert scenario == 'exited-leader'
            except (ValueError, InterruptedError):
                assert scenario != 'exited-leader'
        thread.join(timeout=10)
        assert not thread.is_alive() and not thread_errors, thread_errors
        assert len(owned) == 1 and len(reaped) == 1
        assert not M.group_exists(owned[0].pid)
        if scenario in ('term-leader', 'interrupts'):
            assert (root / 'leader-termed').exists(), 'TERM-responsive leader did not get TERM'
            assert owned[0].returncode == 0
        elif scenario == 'ignoring-leader':
            assert owned[0].returncode == -signal.SIGKILL
        else:
            assert owned[0].returncode == 0
        assert not list(root.glob('release-export-*'))
        size = heartbeat.stat().st_size; time.sleep(.1)
        assert heartbeat.stat().st_size == size
        print(json.dumps({'groupGone': True, 'childReaped': True,
                          'configsRemoved': True, 'writerStopped': True}))
    finally:
        # Failure fallback is fixture-only, not a production cleanup authority.
        for process in owned:
            # Never send a group signal after reaping its identity reservation.
            if process.returncode is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
        thread.join(timeout=2)


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--owned-process-fixture':
        owned_process_fixture(sys.argv[2], sys.argv[3])
    else:
        unittest.main()
