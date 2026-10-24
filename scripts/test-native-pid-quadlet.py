#!/usr/bin/env python3
"""Real installed Quadlet parser only: no systemd selection or container start."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

QUADLET = Path('/usr/libexec/podman/quadlet')


@unittest.skipUnless(QUADLET.is_file(), 'native Quadlet parser unavailable')
class NativePidNamespace(unittest.TestCase):
    def parse(self, directive):
        with tempfile.TemporaryDirectory(prefix='native-pid-quadlet-') as temp:
            root = Path(temp)
            (root / 'native-pid-fixture.container').write_text(
                '[Container]\nImage=docker.io/library/alpine:3.22\n'
                'User=65534:65534\nReadOnly=true\nDropCapability=ALL\n'
                'NoNewPrivileges=true\n' + directive + '\n')
            env = dict(os.environ, QUADLET_UNIT_DIRS=str(root))
            return subprocess.run([str(QUADLET), '--dryrun'], env=env,
                                  capture_output=True, text=True, timeout=10)

    def test_engine_pid_argument_is_supported_without_widening_privileges(self):
        result = self.parse('PodmanArgs=--image-volume=ignore --pid=host')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--pid=host', result.stdout)
        self.assertIn('--user 65534:65534', result.stdout)
        self.assertIn('--read-only', result.stdout)
        self.assertIn('--cap-drop all', result.stdout)
        self.assertIn('no-new-privileges', result.stdout)
        self.assertNotIn('--privileged', result.stdout)


if __name__ == '__main__': unittest.main()
