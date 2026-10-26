"""Source/fake context guards and unprivileged fixed-program refusal only."""
import copy
import json
import subprocess
import sys
import types
import unittest
from unittest.mock import Mock, patch

from p0core import lifecycle as life
from p0core import volumecontext as c
from p0core.volumes import VolumeError


class ProtectedVolumeContextTests(unittest.TestCase):
    def test_mutable_parent_refuses_before_any_native_callback(self):
        actor = types.SimpleNamespace(pw_name='p0-runtime', pw_gid=1004, pw_dir=str(c.HOME))
        runner = Mock()
        with patch.object(life, 'verify_reserves'), patch.object(c.os, 'getuid', return_value=1004), \
             patch.object(c.os, 'geteuid', return_value=1004), patch.object(c.os, 'getgid', return_value=1004), \
             patch.object(c.os, 'getegid', return_value=1004), patch.object(c.os, 'getgroups', return_value=[]), \
             patch.object(c.pwd, 'getpwuid', return_value=actor), patch.object(c.Path, 'home', return_value=c.HOME), \
             patch.object(c.Path, 'cwd', return_value=c.Path('/')), \
             patch.object(c, '_read', return_value=b'0 0 4294967295\n'), \
             patch.object(c, '_directory', side_effect=VolumeError('volume-context-directory')) as directory:
            with self.assertRaisesRegex(VolumeError, '^volume-context-directory$'):
                c.observe(runner)
        directory.assert_called_once_with(c.STACK_PARENT, 0, 0, 0o711)
        runner.assert_not_called()

    def test_actual_pause_view_identity_required_not_only_client_or_raw_uid(self):
        directories = {str(c.STACK_PARENT): {'device': 12, 'inode': 34},
                       str(c.NAMESPACE): {'device': 56, 'inode': 78}}
        expected = {'parent': {'device': 12, 'inode': 34}, 'namespace': {'device': 56, 'inode': 78},
                    'protectedNativeView': True}
        prefix = ['/usr/bin/podman', '--root', '/mnt/stack/p0-v2/rootless/engine']
        runner = Mock(return_value=json.dumps(expected).encode())
        self.assertEqual(c._native_view(runner, prefix, directories), expected)
        self.assertEqual(runner.call_args.args[0], prefix + ['unshare', '/usr/bin/python3', '-I', '-c', c.NATIVE_VIEW_PROGRAM])
        self.assertEqual(runner.call_args.kwargs['timeout'], 30)
        frames = [{}, dict(expected, protectedNativeView=1), dict(expected, extra=True)]
        for key in ('parent', 'namespace'):
            wrong = copy.deepcopy(expected); wrong[key]['inode'] += 1; frames.append(wrong)
        for frame in frames:
            with self.subTest(frame=frame), self.assertRaisesRegex(VolumeError, '^volume-context-native-view$'):
                c._native_view(Mock(return_value=json.dumps(frame).encode()), prefix, directories)

    def test_fixed_program_cannot_certify_normal_host_user_as_namespace_zero(self):
        result = subprocess.run([sys.executable, '-I', '-c', c.NATIVE_VIEW_PROGRAM],
                                input=b'{"parent":{"device":1,"inode":2},"namespace":{"device":3,"inode":4}}',
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout), {'refused': True})
        self.assertEqual(result.stderr, b'')

    def test_reserve_counts_bound_stack_data_not_rootfs_view_parent(self):
        memory = 'MemAvailable: 33554432 kB\n'
        enough = types.SimpleNamespace(f_bavail=300 * 1024**3, f_frsize=1)
        with patch.object(life.Path, 'read_text', return_value=memory), \
             patch.object(life.os, 'statvfs', return_value=enough) as observed:
            life.verify_reserves()
        self.assertEqual([call.args[0] for call in observed.call_args_list], ['/', '/mnt/stack/p0-v2'])
