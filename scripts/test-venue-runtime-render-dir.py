#!/usr/bin/env python3
"""Venue renderer refuses HOME fallback/foreign directories before mutations."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

source=Path(__file__).resolve().parents[1]/'scripts/deploy/render-runtime.sh'

class VenueDir(unittest.TestCase):
    def test_exact_existing_ci_runner_ssh_authority_only(self):
        raw=source.read_text()
        body=raw.split('prepare_host_runtime_dirs() {\n',1)[1].split('\n}\n\nwhile ',1)[0]
        assert 'mkdir -p "$forgejo_runner_ssh_dir"' in body
        code=('set -Eeuo pipefail\n'
              'render_get() { case "$1" in CADDY_VENUE_HTTPS_PORT) printf 56042;; '
              'FORGEJO_RUNNER_SSH_DIR) printf "%s" "$TEST_SSH_DIR";; esac; }\n'
              'prepare_host_runtime_dirs() {\n'+body+'\n}\nprepare_host_runtime_dirs\n')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);state=root/'state';state.mkdir()
            bundle=root/'bundle';bundle.mkdir()
            (bundle/'podman-domains.json').write_text(json.dumps({'domains':[
                {'name':'ci-runner','uid':os.getuid(),'stateRoot':str(state)}]}))
            expected=state/'forgejo-runner-ssh';foreign=root/'foreign';foreign.mkdir()
            sentinel=foreign/'authored';sentinel.write_text('unchanged')
            def run(value):
                return subprocess.run(['bash','-c',code],env={**os.environ,'BUNDLE_ROOT':str(bundle),
                    'TEST_SSH_DIR':str(value)},capture_output=True,text=True,cwd='/',timeout=10)
            self.assertNotEqual(run(expected).returncode,0)
            self.assertFalse(expected.exists())
            self.assertNotEqual(run(foreign).returncode,0)
            self.assertEqual(sentinel.read_text(),'unchanged')
            expected.mkdir(mode=0o700);expected.chmod(0o700)
            before=expected.stat()
            self.assertEqual(run(expected).returncode,0)
            after=expected.stat()
            self.assertEqual((before.st_dev,before.st_ino,before.st_mode),(after.st_dev,after.st_ino,after.st_mode))
            self.assertEqual(sentinel.read_text(),'unchanged')

if __name__=='__main__':unittest.main()
