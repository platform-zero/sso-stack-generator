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
        (self.root / 'podman-domains.json').write_text(json.dumps({'schemaVersion':1,'domains':[]}))

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

    def test_guest_port_mapping_requires_generated_venue_metadata(self):
        import hashlib
        vm=json.loads(self.data)
        vm['network']='p0-venue-r1'
        vm['name']='p0-venue-r1-agents'
        vm['diskRoot']='/mnt/lab_debian/agent_vm/p0-venue-r1-agents'
        vm['servicePorts']={'https':56042,'smtp':56044,'imap':56047}
        self.vm.write_text(json.dumps(vm))
        meta=json.loads(self.meta.read_text());meta['sha256']=hashlib.sha256(self.vm.read_bytes()).hexdigest()
        self.meta.write_text(json.dumps(meta))
        with self.assertRaisesRegex(ValueError,'Legacy guest'):module.verify(self.root)
        mapping={'443':56042,'587':56044,'993':56047}
        (self.root/'podman-domains.json').write_text(json.dumps({'schemaVersion':1,'domains':[],
            'venue':{'portMap':mapping}}))
        self.assertEqual(module.verify(self.root)['site'],'latium')
        vm['name']='p0-agents'
        self.vm.write_text(json.dumps(vm));meta['sha256']=hashlib.sha256(self.vm.read_bytes()).hexdigest()
        self.meta.write_text(json.dumps(meta))
        with self.assertRaisesRegex(ValueError,'Guest private service ports'):module.verify(self.root)
        vm['name']='p0-venue-r1-agents'
        vm['diskRoot']='/mnt/lab_debian/agent_vm/clean-role'
        self.vm.write_text(json.dumps(vm));meta['sha256']=hashlib.sha256(self.vm.read_bytes()).hexdigest()
        self.meta.write_text(json.dumps(meta))
        with self.assertRaisesRegex(ValueError,'Guest private service ports'):module.verify(self.root)
        vm['diskRoot']='/mnt/lab_debian/agent_vm/p0-venue-r1-agents'
        vm['servicePorts']['imap']=56045
        self.vm.write_text(json.dumps(vm));meta['sha256']=hashlib.sha256(self.vm.read_bytes()).hexdigest()
        self.meta.write_text(json.dumps(meta))
        with self.assertRaisesRegex(ValueError,'differ'):module.verify(self.root)

    def test_activation_refuses_missing_or_mixed_control_before_state(self):
        (self.root / 'podman-domains.json').unlink()
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



class StandaloneBundle(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'site').mkdir()
        self.manifest = {'schemaVersion': 2, 'site': 'latium', 'deploymentMode': 'standalone',
                         'storageScope': {'root': '/tmp/standalone-volumes', 'dataClass': 'synthetic'}}
        self.log_root = '/tmp/standalone-volumes/_logs/caddy'
        self.ir = {'services': {'caddy': {'volumes': ['./configs:/etc/caddy:ro', self.log_root + ':/var/log/caddy']}},
                   'volumes': {'caddy_ca': {'hostPath': '/tmp/standalone-volumes/caddy_ca'}}}
        self.domains = {'schemaVersion': 1, 'deploymentMode': 'standalone',
                        'caddyLogRoot': self.log_root, 'domains': [{'uid': 42}],
                        'storageScope': self.manifest['storageScope']}
        self.seal()

    def save(self, path, value):
        body = json.dumps(value).encode()
        (self.root / path).write_bytes(body)
        import hashlib
        return hashlib.sha256(body).hexdigest()

    def seal(self):
        manifest_sha = self.save('site/manifest.json', self.manifest)
        ir_sha = self.save('stack.ir.json', self.ir)
        source_sha = self.save('source-provenance.json', {'manifestSha256': manifest_sha})
        self.save('bundle.json', {'backend': 'podman', 'deploymentMode': 'standalone',
                                 'irSha256': ir_sha, 'sourceProvenanceSha256': source_sha})
        self.save('podman-domains.json', self.domains)

    def test_explicit_standalone_does_not_require_or_activate_guest_roles(self):
        result = module.verify(self.root)
        self.assertEqual(result['agentVm'], 'not-managed')
        self.assertFalse(result['rolesActivated'])

    def test_dedicated_installer_state_root_is_manifest_bound(self):
        self.manifest['installerStateRoot']='/var/lib/stack-fixture'
        self.domains['installerStateRoot']='/var/lib/stack-fixture'; self.seal()
        module.verify(self.root)
        self.domains['installerStateRoot']='/var/lib/stack-other'; self.seal()
        with self.assertRaisesRegex(ValueError,'state root binding'): module.verify(self.root)
        self.manifest['installerStateRoot']=self.domains['installerStateRoot']='/var/lib/platform-zero'
        self.seal()
        with self.assertRaisesRegex(ValueError,'state root binding'): module.verify(self.root)

    def test_mode_tampering_refused(self):
        self.save('site/manifest.json', {**self.manifest, 'components': ['other']})
        with self.assertRaisesRegex(ValueError, 'binding'): module.verify(self.root)

    def test_unknown_mode_refused(self):
        self.manifest['deploymentMode'] = 'skip-checks'; self.seal()
        with self.assertRaisesRegex(ValueError, 'Unknown'): module.verify(self.root)

    def test_guest_spec_or_control_checkout_refused(self):
        with self.assertRaisesRegex(ValueError, 'cannot manage'): module.verify(self.root, self.root)
        self.manifest['agentVmSpec'] = 'agent-vm.json'; self.seal()
        with self.assertRaisesRegex(ValueError, 'cannot manage'): module.verify(self.root)

    def test_managed_role_artifacts_refused(self):
        for name in ('site/agent-vm.json', 'site/agent-vm.provenance.json',
                     'maintenance-workspaces.json', 'software-workspaces.json'):
            p = self.root / name; p.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'role inputs'): module.verify(self.root)
            p.unlink()

    def test_venue_profile_cannot_be_relabelled_standalone(self):
        self.save('podman-domains.json', {'deploymentMode': 'standalone', 'venue': {}, 'domains': []})
        with self.assertRaisesRegex(ValueError, 'binding'): module.verify(self.root)

    def test_unbound_or_old_ingress_log_root_refused(self):
        for value in (None, '/var/log/webservices/caddy', '/tmp/elsewhere'):
            self.domains['caddyLogRoot'] = value; self.seal()
            with self.assertRaisesRegex(ValueError, 'ingress log root'): module.verify(self.root)
        self.domains['caddyLogRoot'] = self.log_root
        self.ir['services']['crowdsec'] = {'volumes': ['/var/log/webservices/caddy:/logs:ro']}; self.seal()
        with self.assertRaisesRegex(ValueError, 'old host logs'): module.verify(self.root)

    def test_missing_or_foreign_storage_scope_refused(self):
        self.domains.pop('storageScope'); self.seal()
        with self.assertRaisesRegex(ValueError, 'storage scope'): module.verify(self.root)
        self.manifest['storageScope'] = {'root': '/', 'dataClass': 'synthetic'}
        self.domains['storageScope'] = self.manifest['storageScope']; self.seal()
        with self.assertRaisesRegex(ValueError, 'storage scope'): module.verify(self.root)

    def test_foreign_journal_uid_scope_refused(self):
        self.ir['services']['alloy'] = {'environment': {'STACK_LOG_UID_REGEX': '0|42'}}; self.seal()
        module.verify(self.root)
        self.ir['services']['alloy']['environment']['STACK_LOG_UID_REGEX'] = '.*'; self.seal()
        with self.assertRaisesRegex(ValueError, 'journal UID scope'): module.verify(self.root)

    def test_missing_or_duplicate_fixed_journal_uids_refused(self):
        self.ir['services']['alloy'] = {'environment': {'STACK_LOG_UID_REGEX': '0|42'}}
        for rows in ([{}], [{'uid': True}], [{'uid': 42}, {'uid': 42}]):
            self.domains['domains'] = rows; self.seal()
            with self.assertRaisesRegex(ValueError, 'journal UID scope'): module.verify(self.root)

    def test_control_socket_access_refused(self):
        for mount in ('/run/p0-control:/run/p0-control:ro',
                      {'source': '/run/p0-control/http.sock', 'target': '/control.sock'}):
            self.ir['services']['caddy']['volumes'] = [mount]; self.seal()
            with self.assertRaisesRegex(ValueError, 'control sockets'): module.verify(self.root)


if __name__ == '__main__': unittest.main()
