#!/usr/bin/env python3
"""Source-only OCI admission/export containment regressions; no live store access."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/package-release-images.py'
SPEC = importlib.util.spec_from_file_location('package_images', SOURCE)
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)


def fixture(path, extra=None, corrupt=False, duplicate=False, arch='amd64'):
    config = json.dumps({'os': 'linux', 'architecture': arch}).encode()
    layer = b'synthetic release layer; no application state'
    def descriptor(body):
        return {'digest': 'sha256:' + hashlib.sha256(body).hexdigest(), 'size': len(body)}
    config_desc, layer_desc = descriptor(config), descriptor(layer)
    manifest = json.dumps({'schemaVersion': 2, 'config': config_desc, 'layers': [layer_desc]}).encode()
    manifest_desc = descriptor(manifest)
    index = json.dumps({'schemaVersion': 2, 'manifests': [manifest_desc]}).encode()
    rows = {'oci-layout': b'{"imageLayoutVersion":"1.0.0"}', 'index.json': index}
    for body in (config, layer, manifest): rows['blobs/sha256/' + hashlib.sha256(body).hexdigest()] = body
    if corrupt: rows['blobs/sha256/' + layer_desc['digest'].split(':')[1]] = b'X' * len(layer)
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
        image = fixture(self.archive)
        before = set(self.root.iterdir())
        M.verify_oci(self.archive, image)
        self.assertEqual(set(self.root.iterdir()), before)

    def test_configuration_id_drift_refused(self):
        fixture(self.archive)
        with self.assertRaisesRegex(ValueError, 'configuration ID'):
            M.verify_oci(self.archive, 'sha256:' + '0' * 64)

    def test_corrupt_layer_refused(self):
        image = fixture(self.archive, corrupt=True)
        with self.assertRaisesRegex(ValueError, 'digest mismatch'): M.verify_oci(self.archive, image)

    def test_duplicate_or_escaping_members_refused(self):
        image = fixture(self.archive, duplicate=True)
        with self.assertRaisesRegex(ValueError, 'ambiguous'): M.verify_oci(self.archive, image)
        image = fixture(self.archive, extra={'../other': b'fixture'})
        with self.assertRaisesRegex(ValueError, 'escaping'): M.verify_oci(self.archive, image)

    def test_unselected_content_is_not_packaged_as_an_experiment_archive(self):
        image = fixture(self.archive, extra={'unrelated-state': b'not an image blob'})
        with self.assertRaisesRegex(ValueError, 'unselected file'): M.verify_oci(self.archive, image)

    def test_linked_member_refused_without_extraction(self):
        image = fixture(self.archive)
        with tarfile.open(self.archive, 'a') as archive:
            entry = tarfile.TarInfo('external-link'); entry.type = tarfile.SYMTYPE; entry.linkname = '/outside'
            archive.addfile(entry)
        with self.assertRaisesRegex(ValueError, 'linked'): M.verify_oci(self.archive, image)
        self.assertEqual({p.name for p in self.root.iterdir()}, {'image.tar'})

    def test_wrong_platform_refused(self):
        image = fixture(self.archive, arch='arm64')
        with self.assertRaisesRegex(ValueError, 'platform'): M.verify_oci(self.archive, image)

    def test_reserve_failure_cancels_only_owned_export_and_never_inherits_secrets(self):
        process = Mock(pid=12345, returncode=None)
        process.poll.return_value = None
        with patch.object(M.subprocess, 'Popen', return_value=process) as start, \
                patch.object(M, 'check_reserves', side_effect=ValueError('reserve refusal')), \
                patch.object(M.os, 'killpg') as kill:
            with self.assertRaisesRegex(ValueError, 'reserve refusal'):
                M.export(['buildah', '--root', '/explicit-cache'], 'sha256:' + '0' * 64,
                         self.root / 'pending', self.root, 5, self.root)
        kill.assert_called_once_with(12345, M.signal.SIGTERM)
        self.assertTrue(start.call_args.kwargs['start_new_session'])
        environment = start.call_args.kwargs['env']
        self.assertEqual(set(environment), {'PATH', 'HOME', 'TMPDIR', 'REGISTRY_AUTH_FILE', 'LANG'})
        self.assertFalse(Path(environment['REGISTRY_AUTH_FILE']).exists())
        self.assertNotIn('--rm', start.call_args.args[0])

    def test_export_deadline_cancels_only_owned_process_group(self):
        process = Mock(pid=45678, returncode=None); process.poll.return_value = None
        with patch.object(M.subprocess, 'Popen', return_value=process), \
                patch.object(M, 'check_reserves'), patch.object(M.time, 'monotonic', side_effect=[0, 2]), \
                patch.object(M.os, 'killpg') as kill:
            with self.assertRaisesRegex(ValueError, 'deadline'):
                M.export(['buildah', '--root', '/explicit-cache'], 'sha256:' + '0' * 64,
                         self.root / 'pending', self.root, 1, self.root)
        kill.assert_called_once_with(45678, M.signal.SIGTERM)


if __name__ == '__main__': unittest.main()
