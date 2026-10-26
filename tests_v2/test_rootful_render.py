"""Rootful store isolation: pure rendering and actual nonexecuting generator."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from p0core.model import Catalog, ContractError
from p0core.render import ROOTFUL_GLOBAL_ARGS, render

IMAGE = 'docker.io/library/alpine@sha256:' + 'a' * 64


def catalog(runtime='rootful', **extra):
    service = {'id': 'edge', 'runtime': runtime, 'image': IMAGE, 'requires': [],
               'networks': ['private'],
               'mounts': [{'kind': 'volume', 'source': 'edge-data', 'target': '/data'}], **extra}
    return Catalog([{'schemaVersion': 1, 'id': 'edge', 'services': [service]}])


class RootfulStoreRenderTests(unittest.TestCase):
    def test_all_rootful_native_resource_types_bind_dedicated_store(self):
        _, files = render(catalog(), ['edge'])
        self.assertEqual(len(files), 3)
        for name, body in files.items():
            with self.subTest(name=name):
                self.assertTrue(name.startswith('quadlet/rootful/p0-v2-'))
                self.assertEqual(body.count('GlobalArgs=' + ROOTFUL_GLOBAL_ARGS), 1)
                self.assertNotIn('/var/lib/containers/storage', body)

    def test_rootless_and_test_units_do_not_inherit_rootful_store(self):
        for runtime in ('rootless', 'test'):
            _, files = render(catalog(runtime), ['edge'])
            for name, body in files.items():
                with self.subTest(runtime=runtime, name=name):
                    self.assertNotIn('GlobalArgs=', body)
                    self.assertNotIn('/mnt/stack/p0-v2/rootful', body)

    def test_system_manager_names_are_reserved_and_rootless_names_unchanged(self):
        for runtime, prefix in (('rootful', 'p0-v2-'), ('rootless', 'p0-'), ('test', 'p0-')):
            graph = catalog(runtime)
            self.assertEqual(graph.services['edge'].unit_name, prefix + 'edge.service')
            _, files = render(graph, ['edge'])
            self.assertIn('quadlet/' + runtime + '/' + prefix + 'edge.container', files)
            self.assertIn('Network=' + prefix + 'network-private.network', files['quadlet/' + runtime + '/' + prefix + 'edge.container'])

    def test_caller_cannot_supply_global_arguments(self):
        for key in ('globalArgs', 'GlobalArgs', 'podmanArgs'):
            with self.subTest(key=key), self.assertRaises(ContractError):
                catalog(**{key: '--root=/var/lib/containers/storage'})

    @unittest.skipUnless(Path('/usr/libexec/podman/quadlet').is_file(), 'native Quadlet generator unavailable')
    def test_actual_generator_scopes_every_native_exec_without_execution(self):
        _, files = render(catalog(), ['edge'])
        with tempfile.TemporaryDirectory(prefix='p0-quadlet-source-') as directory:
            root = Path(directory)
            for name, body in files.items():
                (root/Path(name).name).write_text(body)
            result = subprocess.run(['/usr/libexec/podman/quadlet', '-dryrun', '-no-kmsg-log'],
                                    cwd=root, env={'PATH': '/usr/bin:/bin', 'QUADLET_UNIT_DIRS': str(root)},
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, timeout=15)
            self.assertEqual(result.returncode, 0, 'native generator refused typed fixture')
            executions = [line for line in result.stdout.splitlines()
                          if line.startswith('Exec') and '/usr/bin/podman ' in line]
            self.assertGreaterEqual(len(executions), 3)
            for line in executions:
                with self.subTest(directive=line.split('=', 1)[0]):
                    for flag in ROOTFUL_GLOBAL_ARGS.split():
                        self.assertIn(flag, line)
                    self.assertNotIn('/var/lib/containers/storage', line)
            self.assertIn('p0-v2-network-private', result.stdout)
            self.assertIn('p0-v2-edge-data', result.stdout)
            self.assertIn('p0-v2-edge.service', result.stdout)
            self.assertIn('VolumeName=p0-edge-data', files['quadlet/rootful/p0-v2-edge-data.volume'])
