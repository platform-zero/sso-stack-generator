"""Actual unprivileged process inheritance only, never native application stores."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from p0core.lifecycle import OperationError, Runner


class RunnerDescriptorTests(unittest.TestCase):
    def test_only_one_held_directory_reaches_child_and_remains_caller_owned(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryFile() as other:
            held = os.open(root, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                expected = os.fstat(held)
                program = (
                    'import json,os,stat,sys; '
                    's=os.fstat(int(sys.argv[1])); '
                    'r={"directory":stat.S_ISDIR(s.st_mode),"device":s.st_dev,"inode":s.st_ino}; '
                    '\ntry: os.fstat(int(sys.argv[2])); r["otherInherited"]=True'
                    '\nexcept OSError: r["otherInherited"]=False'
                    '\nprint(json.dumps(r))'
                )
                raw = Runner()(['/usr/bin/python3', '-I', '-c', program, str(held), str(other.fileno())],
                               pass_fds=(held,))
                self.assertEqual(json.loads(raw), {'directory': True, 'device': expected.st_dev,
                                                  'inode': expected.st_ino, 'otherInherited': False})
                self.assertEqual(os.fstat(held).st_ino, expected.st_ino)
                self.assertFalse(os.get_inheritable(held))
            finally:
                os.close(held)

    def test_descriptor_shape_and_kind_refuse_before_spawn(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryFile() as regular:
            held = os.open(root, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                for descriptors in ([held], (held, held), (True,), (0,), (2,), ('3',),
                                    (987654321,), (regular.fileno(),)):
                    with self.subTest(descriptors=descriptors), patch('subprocess.Popen') as spawn:
                        with self.assertRaises(OperationError):
                            Runner()(['/usr/bin/true'], pass_fds=descriptors)
                        spawn.assert_not_called()
            finally:
                os.close(held)

    def test_default_does_not_inherit_even_directory(self):
        with tempfile.TemporaryDirectory() as root:
            held = os.open(root, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                program = ('import os,sys\ntry: os.fstat(int(sys.argv[1])); print("inherited")'
                           '\nexcept OSError: print("closed")')
                self.assertEqual(Runner()(['/usr/bin/python3', '-I', '-c', program, str(held)]), b'closed\n')
            finally:
                os.close(held)


if __name__ == '__main__':
    unittest.main()
