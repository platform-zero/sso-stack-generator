#!/usr/bin/env python3
"""Source-only staging regressions. All mutations are confined to private temp dirs."""
import fcntl
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

INSTALLER = Path(__file__).resolve().with_name('install-bundle.sh')
WRAPPERS = ('deploy.sh', 'verify.sh', 'run-tests.sh', 'stackctl', 'install.sh')


class StagingSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='stack-install-source-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dist = self.root / 'dist'
        self.target = self.root / 'target'
        (self.dist / 'build/scripts').mkdir(parents=True)
        (self.dist / 'build/reports').mkdir()
        (self.dist / 'build/payload.txt').write_text('first\n')
        (self.dist / 'build/scripts/deploy.sh').write_text('#!/bin/sh\nexit 0\n')
        for name in WRAPPERS:
            (self.dist / name).write_text('#!/bin/sh\nexit 0\n')

    def run_install(self, target=None, env=None):
        return subprocess.run(['bash', str(INSTALLER), '--dist-root', str(self.dist),
                               '--target', str(target or self.target)],
                              capture_output=True, text=True, timeout=10, env=env)

    def test_unknown_destination_data_refused_and_preserved(self):
        self.target.mkdir()
        (self.target / 'authored.txt').write_text('keep\n')
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.target / 'authored.txt').read_text(), 'keep\n')
        self.assertFalse((self.target / 'build').exists())

    def test_source_parent_target_refused_without_mutation(self):
        result = self.run_install(self.root)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.dist / 'build/payload.txt').read_text(), 'first\n')

    def test_target_inside_source_refused(self):
        result = self.run_install(self.dist / 'nested')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.dist / 'nested').exists())

    def test_symlink_target_refused(self):
        real = self.root / 'authored'
        real.mkdir()
        (real / 'keep').write_text('keep\n')
        self.target.symlink_to(real, target_is_directory=True)
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertEqual((real / 'keep').read_text(), 'keep\n')

    def test_previous_build_retained_and_runtime_preserved(self):
        self.assertEqual(self.run_install().returncode, 0)
        (self.target / 'runtime/keep').write_text('runtime\n')
        (self.dist / 'build/payload.txt').write_text('second\n')
        self.assertEqual(self.run_install().returncode, 0)
        self.assertEqual((self.target / 'build/payload.txt').read_text(), 'second\n')
        self.assertEqual((self.target / 'build.previous/payload.txt').read_text(), 'first\n')
        self.assertEqual((self.target / 'runtime/keep').read_text(), 'runtime\n')

    def test_unknown_data_in_managed_destination_preserved(self):
        self.assertEqual(self.run_install().returncode, 0)
        (self.target / 'private-source').mkdir()
        (self.target / 'private-source/keep').write_text('keep\n')
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertEqual((self.target / 'private-source/keep').read_text(), 'keep\n')
        self.assertEqual((self.target / 'build/payload.txt').read_text(), 'first\n')

    def test_missing_wrapper_refuses_before_replacing_build(self):
        self.assertEqual(self.run_install().returncode, 0)
        (self.dist / 'verify.sh').unlink()
        (self.dist / 'build/payload.txt').write_text('second\n')
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertEqual((self.target / 'build/payload.txt').read_text(), 'first\n')

    def test_linked_bundle_payload_refused(self):
        external = self.root / 'external'
        external.write_text('keep\n')
        (self.dist / 'build/linked').symlink_to(external)
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertFalse((self.target / 'build').exists())
        self.assertEqual(external.read_text(), 'keep\n')

    def test_interrupted_pending_stage_refuses_replay(self):
        self.assertEqual(self.run_install().returncode, 0)
        (self.target / '.webservices-install-pending').write_text('.install.next.old\n')
        (self.dist / 'build/payload.txt').write_text('second\n')
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertEqual((self.target / 'build/payload.txt').read_text(), 'first\n')

    def test_concurrent_staging_refuses(self):
        self.target.mkdir()
        with (self.target / '.webservices-install.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertNotEqual(self.run_install().returncode, 0)
        self.assertFalse((self.target / 'build').exists())

    def test_symlink_lock_refused_without_truncating_external_file(self):
        self.target.mkdir()
        external = self.root / 'external-lock'
        external.write_text('keep\n')
        (self.target / '.webservices-install.lock').symlink_to(external)
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertEqual(external.read_text(), 'keep\n')

    def test_hardlinked_lock_refused_without_truncating_external_file(self):
        self.target.mkdir()
        external = self.root / 'external-lock'
        external.write_text('keep\n')
        os.link(external, self.target / '.webservices-install.lock')
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertEqual(external.read_text(), 'keep\n')

    def fail_move(self, suffix):
        self.assertEqual(self.run_install().returncode, 0)
        (self.dist / 'build/payload.txt').write_text('second\n')
        fake = self.root / 'fake-bin'
        fake.mkdir()
        command = fake / 'mv'
        command.write_text('#!/bin/sh\nfor arg in "$@"; do\n'
                           '  case "$arg" in */new/' + suffix + ') exit 73;; esac\n'
                           'done\nexec /usr/bin/mv "$@"\n')
        command.chmod(0o700)
        env = dict(os.environ, PATH=str(fake) + ':' + os.environ['PATH'])
        self.assertNotEqual(self.run_install(env=env).returncode, 0)
        self.assertEqual((self.target / 'build/payload.txt').read_text(), 'first\n')
        self.assertFalse((self.target / '.webservices-install-pending').exists())
        self.assertEqual((self.target / 'verify.sh').read_text(), '#!/bin/sh\nexit 0\n')

    def test_build_move_failure_restores_previous_selection(self):
        self.fail_move('build')

    def test_wrapper_move_failure_restores_previous_selection(self):
        self.fail_move('verify.sh')


if __name__ == '__main__':
    unittest.main()
