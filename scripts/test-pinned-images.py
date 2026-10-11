#!/usr/bin/env python3
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

path = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/install-pinned-images.py'
spec = importlib.util.spec_from_file_location('pinned_images', path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


@unittest.skipUnless(os.geteuid() == 0, 'protected image fixtures require root')
class PinnedImages(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.image = 'sha256:' + 'a' * 64
        self.ir = {'services': {'selected': {'image': self.image, 'updatePolicy': 'pinned',
                   'placement': 'rootless', 'rootlessDomain': 'apps'}}}
        (self.root / 'stack.ir.json').write_text(json.dumps(self.ir))
        (self.root / 'podman-domains.json').write_text(json.dumps({'domains': [{'name': 'apps', 'user': 'service-apps'}]}))
        self.archive = self.root / 'release.tar'
        self.archive.write_bytes(b'fixture release input')
        self.row = {'image': self.image, 'archiveFilename': self.archive.name,
                    'archiveSha256': hashlib.sha256(self.archive.read_bytes()).hexdigest()}
        self.inputs = self.root / 'inputs.json'
        self.save()

    def save(self):
        self.inputs.write_text(json.dumps({'schemaVersion': 1, 'images': [self.row]}))

    def tearDown(self):
        self.tmp.cleanup()

    def test_selected_authority_only(self):
        self.assertEqual(mod.validate(self.root, self.inputs), [(self.image, self.archive, ['service-apps'])])

    def test_tampered_archive_refused(self):
        self.archive.write_bytes(b'tampered')
        with self.assertRaises(ValueError): mod.validate(self.root, self.inputs)

    def test_writable_input_refused(self):
        self.inputs.chmod(0o666)
        with self.assertRaises(ValueError): mod.validate(self.root, self.inputs)

    def test_symlink_archive_refused(self):
        target = self.root / 'target'; self.archive.rename(target); self.archive.symlink_to(target)
        with self.assertRaises(ValueError): mod.validate(self.root, self.inputs)

    def test_traversal_refused(self):
        self.row['archiveFilename'] = '../release.tar'; self.save()
        with self.assertRaises(ValueError): mod.validate(self.root, self.inputs)

    def test_unselected_image_refused(self):
        self.row['image'] = 'sha256:' + 'b' * 64; self.save()
        with self.assertRaises(ValueError): mod.validate(self.root, self.inputs)

    def test_missing_input_refused(self):
        self.inputs.write_text(json.dumps({'schemaVersion': 1, 'images': []}))
        with self.assertRaises(ValueError): mod.validate(self.root, self.inputs)

    def test_registry_update_refused(self):
        self.ir['services']['selected']['updatePolicy'] = 'registry'
        (self.root / 'stack.ir.json').write_text(json.dumps(self.ir))
        with self.assertRaises(ValueError): mod.validate(self.root, self.inputs)


if __name__ == '__main__':
    unittest.main()
