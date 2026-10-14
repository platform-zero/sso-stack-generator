#!/usr/bin/env python3
"""Execute the selected-target-only cold-daemon restart with a fake user manager."""
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/install-podman-bundle.sh'
START = 'start_missing_rootless_daemons() {'


class MissedColdDaemon(unittest.TestCase):
    def test_only_inactive_healthy_selected_daemon_starts(self):
        text = SOURCE.read_text()
        fn = text[text.index(START):text.index('\n}\n', text.index(START)) + 3]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'webservices-apps.target'
            target.write_text('[Unit]\nWants=webservices-legal-research-mcp.service '
                              'webservices-running.service webservices-bootstrap.service '
                              'webservices-queued.service webservices-drifted.service\n')
            script = '''set -euo pipefail
ROOTLESS_DOMAIN_NAMES=(apps)
ROOTLESS_SYSTEMD_DIRS=("$1")
START_LOG="$2"
user_systemctl() {
  local index="$1" operation="$2" unit="$3"
  if [ "$operation" = show ]; then
    case "$unit" in
      webservices-legal-research-mcp.service)
        printf 'Type=notify\\nActiveState=inactive\\nResult=success\\nJob=\\nLoadState=loaded\\n' ;;
      webservices-running.service)
        printf 'Type=notify\\nActiveState=active\\nResult=success\\nJob=\\nLoadState=loaded\\n' ;;
      webservices-bootstrap.service)
        printf 'Type=oneshot\\nActiveState=inactive\\nResult=success\\nJob=\\nLoadState=loaded\\n' ;;
      webservices-queued.service)
        printf 'Type=notify\\nActiveState=inactive\\nResult=success\\nJob=42\\nLoadState=loaded\\n' ;;
      webservices-drifted.service)
        printf 'Type=notify\\nActiveState=inactive\\nResult=success\\nJob=\\nLoadState=not-found\\n' ;;
      *) return 1 ;;
    esac
  elif [ "$operation" = --no-block ] && [ "$unit" = start ]; then
    printf '%s\\n' "$4" >> "$START_LOG"
  else
    return 1
  fi
}
'''
            log = Path(directory) / 'started'
            completed = subprocess.run(['bash', '-c', script + fn + '\nstart_missing_rootless_daemons\n',
                                        'fixture', directory, str(log)],
                                       text=True, capture_output=True, timeout=25)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(log.read_text().splitlines(), ['webservices-legal-research-mcp.service'])

    def test_unselected_unit_name_fails_closed(self):
        text = SOURCE.read_text()
        self.assertLess(text.index('wait_for_cross_domain_producers\nretry_failed_rootless_services\n'
                                   'start_missing_rootless_daemons\nretry_failed_rootless_services'),
                        text.index('wait_for_target_services rootless'))
        fn = text[text.index(START):text.index('\n}\n', text.index(START)) + 3]
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'webservices-apps.target').write_text('Wants=ssh.service\n')
            completed = subprocess.run(['bash', '-c',
                                        'ROOTLESS_DOMAIN_NAMES=(apps); ROOTLESS_SYSTEMD_DIRS=("$1"); '
                                        + fn + '\nstart_missing_rootless_daemons\n', 'fixture', directory],
                                       text=True, capture_output=True, timeout=10)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn('invalid selected daemon unit name', completed.stderr)


if __name__ == '__main__':
    unittest.main()
