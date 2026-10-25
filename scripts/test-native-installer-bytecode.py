#!/usr/bin/env python3
"""Isolated prologue regression; no host/native lifecycle or service imports."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest


class NativeHelperNamespace(unittest.TestCase):
    def test_import_does_not_mutate_pinned_namespace(self):
        source = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/install-podman-bundle.sh'
        prologue = source.read_text().split('BUNDLE=""', 1)[0]
        self.assertIn('export PYTHONDONTWRITEBYTECODE=1', prologue)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'fixture_helper.py').write_text('VALUE = 1\n')
            env = dict(os.environ)
            env.pop('PYTHONDONTWRITEBYTECODE', None)
            subprocess.run(['bash', '-c', prologue + '\npython3 -c "import fixture_helper"'],
                           cwd=root, env=env, check=True, timeout=10)
            self.assertEqual({p.name for p in root.iterdir()}, {'fixture_helper.py'})


if __name__ == '__main__':
    unittest.main()
