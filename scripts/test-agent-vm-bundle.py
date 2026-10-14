#!/usr/bin/env python3
"""No mutation before missing/ambiguous/tampered site runtime pins are refused."""
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/verify-agent-vm-bundle.py'
spec = importlib.util.spec_from_file_location('agent_vm_bundle', SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SITE = Path(__file__).resolve().parents[2] / 'site-config-first-install/sites/latium'


class BundlePins(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.site = Path(self.tmp.name) / 'site'
        self.site.mkdir()
        self.vm = self.site / 'agent-vm.json'
        self.manifest = json.loads((SITE / 'manifest.json').read_text())
        self.data = (SITE / 'agent-vm.json').read_bytes()
        self.vm.write_bytes(self.data)
        self.site.joinpath('manifest.json').write_text(json.dumps(self.manifest))
        self.meta = self.site / 'agent-vm.provenance.json'
        import hashlib
        self.meta.write_text(json.dumps({'schemaVersion': 1, 'path': 'agent-vm.json',
            'sha256': hashlib.sha256(self.data).hexdigest(),
            'controlCommit': json.loads(self.data)['runtime']['controlCommit']}))
        self.root = self.site.parent

    def test_exact_site_contract(self):
        result = module.verify(self.root)
        self.assertFalse(result['rolesActivated'])
        self.assertFalse(result['controlSourceValidated'])
        self.assertEqual(result['controlCommit'], json.loads(self.data)['runtime']['controlCommit'])

    def test_missing_or_retargeted_site_pin(self):
        self.manifest.pop('agentVmSpec')
        self.site.joinpath('manifest.json').write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(ValueError, 'requires exact'): module.verify(self.root)
        self.manifest['agentVmSpec'] = '../other.json'
        self.site.joinpath('manifest.json').write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(ValueError, 'requires exact'): module.verify(self.root)

    def test_changed_pin_and_duplicate_authority(self):
        self.vm.write_bytes(self.data + b' ')
        with self.assertRaisesRegex(ValueError, 'provenance'): module.verify(self.root)
        self.vm.write_bytes(self.data.replace(b'"controlCommit":', b'"controlCommit":"' + b'0' * 40 + b'", "controlCommit":'))
        with self.assertRaisesRegex(ValueError, 'Duplicate'): module.verify(self.root)

    def test_oversized_vm_input_refused_before_digest(self):
        self.vm.write_bytes(self.data + b' ' * 65536)
        with self.assertRaisesRegex(ValueError, 'oversized'): module.verify(self.root)

    def test_invalid_cpu_and_symlink(self):
        vm = json.loads(self.data); vm['projectLanes'] = ['unexpected']
        self.vm.write_text(json.dumps(vm))
        import hashlib
        metadata = json.loads(self.meta.read_text()); metadata['sha256'] = hashlib.sha256(self.vm.read_bytes()).hexdigest()
        self.meta.write_text(json.dumps(metadata))
        with self.assertRaisesRegex(ValueError, 'empty CPU'): module.verify(self.root)
        self.vm.unlink(); self.vm.symlink_to(SITE / 'agent-vm.json')
        with self.assertRaisesRegex(ValueError, 'linked'): module.verify(self.root)

    def test_mixed_control_commit_refused(self):
        with self.assertRaisesRegex(ValueError, 'checkout differs'): module.verify(
            self.root, Path(__file__).resolve().parents[1])

    def test_activation_refuses_missing_or_mixed_control_before_state(self):
        ops = self.root / 'ops'; ops.mkdir()
        shutil.copyfile(SOURCE, ops / SOURCE.name)
        (self.root / 'quadlet').mkdir()
        script = SOURCE.with_name('install-podman-bundle.sh')
        for extra in ([], ['--control-checkout', str(self.root)]):
            result = subprocess.run(['bash', str(script), '--bundle', str(self.root), '--activate', *extra],
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('preflight passed', result.stdout + result.stderr)
            self.assertFalse((self.root / 'podman-domains.json').exists())



if __name__ == '__main__': unittest.main()
