#!/usr/bin/env python3
"""Focused source shell regression: host role failure precedes activation."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/install-podman-bundle.sh'

class HostRolePreflight(unittest.TestCase):
    def run_guard(self, *, active, directory_valid=True, activate=True, mount=True):
        source = SOURCE.read_text()
        block = source[source.index('# The selected P0 Caddy route'):source.index("printf '[podman-install] preflight passed")]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'caddy.container').write_text('Volume=/run/p0-control:/run/p0-control:ro\n' if mount else '[Container]\n')
            script = ('set -e\nROOTFUL_QUADLET_SOURCE=' + str(root) + '\nACTIVATE=' + str(activate).lower() + '\n'
                      + 'systemctl() { return ' + ('0' if active else '1') + '; }\n'
                      + 'python3() { command python3 -c "import sys; sys.exit(' + ('0' if directory_valid else '1') + ')"; }\n'
                      + block + '\nprintf activation-reached\n')
            return subprocess.run(['bash', '-c', script], text=True, capture_output=True)

    def test_serial_builds_are_scoped_ordered_and_fail_closed(self):
        source = SOURCE.read_text()
        functions = source[source.index('selected_container_units()'):source.index('cancel_webservices_start_jobs()')]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for name in ('webservices-b.build', 'webservices-a.build', 'foreign.build', 'webservices-a.container', 'webservices-core.target'):
                (root / name).touch()
            script = 'set -e\n' + functions + '\nsystemctl() { printf "%s\\n" "$*"; }\nbuild_selected_serially rootful 0 ' + str(root)
            result = subprocess.run(['bash', '-c', script], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0)
            calls = [l for l in result.stdout.splitlines() if l.startswith('restart ')]
            self.assertEqual(calls, ['restart webservices-a-build.service', 'restart webservices-b-build.service'])
            failure = script.replace('printf "%s\\n" "$*";', 'return 1;')
            result = subprocess.run(['bash', '-c', failure], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('webservices-b-build', result.stdout)
            selected = subprocess.check_output(['bash', '-c', functions + '\nselected_container_units ' + str(root)], text=True)
            self.assertIn('webservices-core.target', selected)
            self.assertNotIn('foreign', selected)

    def test_failure_cleanup_is_always_armed_before_startup(self):
        source = SOURCE.read_text()
        self.assertIn('WEBSERVICES_ACTIVATION_ROLLBACK:-0', source)
        self.assertLess(source.index('trap rollback ERR'), source.index('restart_rootful_network_units\n'))
        rollback = source[source.index('rollback() {'):source.index('wait_for_target_services() {')]
        self.assertIn('stop_selected_services rootful', rollback)
        self.assertIn('stop_selected_services rootless', rollback)
        self.assertLess(rollback.index('scoped stop incomplete'), rollback.index('explicit release rollback requested'))
        self.assertIn('no automatic restart', rollback)

    def test_missing_host_refuses_activation(self):
        r = self.run_guard(active=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('site-pinned host control role', r.stderr)
        self.assertNotIn('activation-reached', r.stdout)

    def test_unsafe_directory_refuses_activation(self):
        self.assertNotEqual(self.run_guard(active=True, directory_valid=False).returncode, 0)

    def test_valid_role_reaches_activation(self):
        self.assertEqual(self.run_guard(active=True).returncode, 0)

    def test_validation_only_and_non_p0_bundle_remain_supported(self):
        self.assertEqual(self.run_guard(active=False, activate=False).returncode, 0)
        self.assertEqual(self.run_guard(active=False, mount=False).returncode, 0)

if __name__ == '__main__': unittest.main()
