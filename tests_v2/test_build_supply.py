import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / 'ops/host-admin/stage-p0-build-context.py'
SPEC = importlib.util.spec_from_file_location('build_supply', PATH)
SUPPLY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUPPLY)


class BuildSupplyTests(unittest.TestCase):
    def test_exact_regular_operator_source_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'source'
            path.write_bytes(b'synthetic-code')
            checksum = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(SUPPLY.read_file(path, checksum, os.getuid()), b'synthetic-code')
            with self.assertRaises(SUPPLY.Refused):
                SUPPLY.read_file(path, '0' * 64, os.getuid())
            with self.assertRaises(SUPPLY.Refused):
                SUPPLY.read_file(path, checksum, os.getuid() + 1)
            os.link(path, Path(directory) / 'hardlink')
            with self.assertRaises(SUPPLY.Refused):
                SUPPLY.read_file(path, checksum, os.getuid())

    def test_symlink_and_duplicate_manifest_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'source').write_bytes(b'synthetic-code')
            (root / 'link').symlink_to(root / 'source')
            with self.assertRaises(OSError):
                SUPPLY.read_file(root / 'link', '0' * 64, os.getuid())
        with self.assertRaises(SUPPLY.Refused):
            SUPPLY.pairs([('files', {}), ('files', {})])

    def test_never_imports_core_or_builds_as_root(self):
        source = PATH.read_text()
        self.assertNotIn('subprocess', source)
        self.assertNotIn('p0core', source)
        self.assertNotIn('os.system', source)
