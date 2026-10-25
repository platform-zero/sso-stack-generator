import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'ops/host-admin/provision-p0-runtime.py'
SPEC = importlib.util.spec_from_file_location('runtime_bootstrap', PATH)
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


class BootstrapTests(unittest.TestCase):
    def test_directory_owner_mode_and_symlink_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'runtime'
            self.assertFalse(bootstrap.private_directory(path, os.getuid(), os.getgid(), create=False))
            self.assertTrue(bootstrap.private_directory(path, os.getuid(), os.getgid(), create=True))
            path.chmod(0o755)
            with self.assertRaises(bootstrap.Refused):
                bootstrap.private_directory(path, os.getuid(), os.getgid(), create=False)
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises(bootstrap.Refused):
                bootstrap.private_directory(link, os.getuid(), os.getgid(), create=False)

    def test_fresh_creation_normalizes_inherited_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'namespace'
            previous = os.umask(0o077)
            try:
                bootstrap.private_directory(path, os.getuid(), os.getgid(), create=True, mode=0o711)
            finally:
                os.umask(previous)
            self.assertEqual(path.stat().st_mode & 0o7777, 0o711)

    def test_created_namespace_recovery_exact_identity_and_empty_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'namespace'
            path.mkdir()
            observed = path.stat()
            synthetic = SimpleNamespace(st_dev=observed.st_dev, st_ino=observed.st_ino,
                                        st_uid=0, st_gid=0, st_mode=0o42710)
            identity = f'{observed.st_dev}:{observed.st_ino}'
            with patch.object(bootstrap, 'STACK', path), \
                 patch.object(bootstrap.os, 'fstat', return_value=synthetic), \
                 patch.object(bootstrap.os, 'fchmod') as chmod:
                bootstrap.finish_created_namespace(identity)
                chmod.assert_called_once()
                with self.assertRaises(bootstrap.Refused):
                    bootstrap.finish_created_namespace('0:0')
                (path / 'protected').write_text('do not touch')
                with self.assertRaises(bootstrap.Refused):
                    bootstrap.finish_created_namespace(identity)

    def test_read_only_missing_account_does_not_run_commands(self):
        with patch.object(bootstrap.os, 'geteuid', return_value=0), \
             patch.object(bootstrap, 'reserves'), \
             patch.object(bootstrap, 'account', return_value=None), \
             patch.object(bootstrap, 'command') as command:
            bootstrap.main([])
            command.assert_not_called()

    def test_wrong_account_is_not_adopted(self):
        wrong = SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_dir='/home/wrong', pw_shell='/usr/sbin/nologin')
        with patch.object(bootstrap.pwd, 'getpwnam', return_value=wrong):
            with self.assertRaises(bootstrap.Refused):
                bootstrap.account()

    def test_existing_user_cannot_have_supplementary_privileges(self):
        entry = SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_dir=str(bootstrap.HOME), pw_shell='/usr/sbin/nologin')
        group = SimpleNamespace(gr_name='p0-runtime', gr_mem=[])
        with patch.object(bootstrap.pwd, 'getpwnam', return_value=entry), \
             patch.object(bootstrap.grp, 'getgrgid', return_value=group), \
             patch.object(bootstrap.grp, 'getgrall', return_value=[SimpleNamespace(gr_mem=['p0-runtime'])]):
            with self.assertRaises(bootstrap.Refused):
                bootstrap.account()

    def test_subordinate_range_overlap_refused(self):
        entry = SimpleNamespace(pw_uid=1001)
        with patch.object(bootstrap.Path, 'read_text', return_value='p0-runtime:100000:65536\nother:150000:65536\n'):
            with self.assertRaises(bootstrap.Refused):
                bootstrap.subordinate_ranges(entry)

    def test_missing_subordinate_ranges_refused(self):
        with patch.object(bootstrap.Path, 'read_text', return_value='other:100000:65536\n'):
            with self.assertRaises(bootstrap.Refused):
                bootstrap.subordinate_ranges(SimpleNamespace(pw_uid=1001))

    def test_new_namespace_allows_traverse_without_listing_or_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'namespace'
            bootstrap.private_directory(path, os.getuid(), os.getgid(), create=True, mode=0o711)
            self.assertEqual(path.stat().st_mode & 0o777, 0o711)


if __name__ == '__main__':
    unittest.main()
