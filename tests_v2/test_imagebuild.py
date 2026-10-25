import json
from pathlib import Path
import tempfile
import unittest

from p0core.imagebuild import pack, verify
from p0core.model import ContractError
from p0core.lifecycle import Runner, OperationError


class ContextTests(unittest.TestCase):
    def source(self, directory):
        root = Path(directory) / 'source'
        root.mkdir()
        (root / 'Containerfile').write_text('FROM registry.invalid/base@sha256:' + 'a' * 64 + '\nCOPY app.py /app.py\n')
        (root / 'app.py').write_text('print("synthetic")\n')
        return root

    def test_deterministic_explicit_context_does_not_copy_private_or_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.source(directory)
            (root / '.env').write_text('never-copy')
            (root / 'historical').mkdir()
            (root / 'historical/old.py').write_text('never-execute')
            first = pack(root, Path(directory) / 'first', 'example', ['Containerfile', 'app.py'])
            second = pack(root, Path(directory) / 'second', 'example', ['app.py', 'Containerfile'])
            self.assertEqual(first['sha256'], second['sha256'])
            lock = verify(first['context'], first['sha256'])
            self.assertEqual(set(lock['files']), {'Containerfile', 'app.py'})
            self.assertFalse((Path(first['context']) / '.env').exists())

    def test_changed_or_unlisted_or_symlink_members_refused(self):
        for variant in ('changed', 'extra', 'symlink'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = self.source(directory)
                output = Path(directory) / 'context'
                result = pack(root, output, 'example', ['Containerfile', 'app.py'])
                if variant == 'changed':
                    (output / 'app.py').write_text('different')
                elif variant == 'extra':
                    (output / 'extra').write_text('unlisted')
                else:
                    (output / 'link').symlink_to(root, target_is_directory=True)
                with self.assertRaises(ContractError):
                    verify(output, result['sha256'])

    def test_mutable_base_and_unsafe_inputs_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.source(directory)
            for include in ('../private', '.env', 'historical/input.py'):
                with self.assertRaises(ContractError):
                    pack(root, Path(directory) / 'no-output', 'example', ['Containerfile', include])
            (root / 'Containerfile').write_text('FROM registry.invalid/base:latest\n')
            with self.assertRaises(ContractError):
                pack(root, Path(directory) / 'no-output', 'example', ['Containerfile', 'app.py'])

    def test_internal_stage_alias_is_not_mutable_external_image(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.source(directory)
            (root / 'Containerfile').write_text('FROM registry.invalid/base@sha256:' + 'a' * 64 + ' AS builder\nFROM builder\n')
            result = pack(root, Path(directory) / 'context', 'example', ['Containerfile', 'app.py'])
            self.assertEqual(len(verify(result['context'], result['sha256'])['baseImages']), 1)


class RunnerBoundsTests(unittest.TestCase):
    def test_success_and_stdin_use_actual_owned_process(self):
        output = Runner()(['/usr/bin/python3', '-I', '-c', 'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())'], input_bytes=b'synthetic-only')
        self.assertEqual(output, b'synthetic-only')

    def test_oversized_output_is_stopped_while_streaming(self):
        with self.assertRaisesRegex(OperationError, 'response exceeds bound'):
            Runner()(['/usr/bin/python3', '-I', '-c', 'import sys; sys.stdout.buffer.write(b"x" * 2097152)'])

    def test_deadline_and_input_bound(self):
        with self.assertRaisesRegex(OperationError, 'timed out'):
            Runner()(['/usr/bin/python3', '-I', '-c', 'import time; time.sleep(20)'], timeout=0.05)
        with self.assertRaisesRegex(OperationError, 'input exceeds bound'):
            Runner()(['/usr/bin/false'], input_bytes=b'x' * 4097)
