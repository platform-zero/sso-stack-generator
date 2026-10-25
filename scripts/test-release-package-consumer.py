#!/usr/bin/env python3
"""Synthetic source/proof/OCI consumer contracts; no installation or host calls."""
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/install-pinned-images.py'
SPEC = importlib.util.spec_from_file_location('consumer', SOURCE)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
OCI = 'application/vnd.oci.image.'


def sha(body):
    return hashlib.sha256(body).hexdigest()


def fixture(path, *, reverse=False, corrupt=False, diff_drift=False):
    layers = []
    for text in (b'first synthetic capability', b'second synthetic capability'):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w') as archive:
            entry = tarfile.TarInfo('usr/share/synthetic'); entry.size = len(text)
            archive.addfile(entry, io.BytesIO(text))
        layers.append(output.getvalue())
    diff_ids = ['sha256:' + sha(layer) for layer in layers]
    if diff_drift:
        diff_ids[0] = 'sha256:' + '0' * 64
    config = json.dumps({'os': 'linux', 'architecture': 'amd64',
                         'rootfs': {'type': 'layers', 'diff_ids': diff_ids}}).encode()
    def desc(body, kind):
        return {'mediaType': OCI + kind, 'digest': 'sha256:' + sha(body), 'size': len(body)}
    zipped = [gzip.compress(layer, mtime=0) for layer in layers]
    descriptors = [desc(layer, 'layer.v1.tar+gzip') for layer in zipped]
    manifest = json.dumps({'schemaVersion': 2, 'config': desc(config, 'config.v1+json'),
                           'layers': list(reversed(descriptors)) if reverse else descriptors}).encode()
    blobs = {'oci-layout': b'{"imageLayoutVersion":"1.0.0"}',
             'index.json': json.dumps({'schemaVersion': 2, 'manifests': [desc(manifest, 'manifest.v1+json')]}).encode()}
    for body in (config, manifest, *zipped):
        blobs['blobs/sha256/' + sha(body)] = body
    if corrupt:
        blobs['blobs/sha256/' + sha(config)] = b'X' * len(config)
    with tarfile.open(path, 'w') as archive:
        for name, body in blobs.items():
            entry = tarfile.TarInfo(name); entry.size = len(body)
            archive.addfile(entry, io.BytesIO(body))
    return 'sha256:' + sha(config)


class Consumer(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / 'candidate'; self.bundle.mkdir(mode=0o700)
        (self.bundle / 'site').mkdir(); (self.bundle / 'ops').mkdir()
        self.output = self.root / 'output'; self.output.mkdir(mode=0o700)
        self.inputs = self.output / 'image-inputs.json'
        self.proofpath = self.output / 'release-image-proof.json'
        self.archive = self.output / 'selected.oci.tar'
        self.image = fixture(self.archive)
        self.archive.chmod(0o600)
        self.ir = {'modules': [], 'quadletBuildImagesFrozen': True, 'services': {
            'producer': {'image': self.image, 'frozenBuildImage': self.image, 'build': {},
                         'placement': 'rootful', 'updatePolicy': 'pinned'},
            'ondemand': {'image': self.image, 'frozenBuildImage': self.image, 'build': {},
                         'lifecycle': 'on-demand', 'quadletManaged': False,
                         'placement': 'rootful', 'updatePolicy': 'pinned'}}}
        self.manifest = {'deploymentMode': 'standalone', 'localBuildImagePinsPath': 'pins.json'}
        self.provenance = {'generatorDirty': False, 'siteDirty': False, 'modules': [],
                           'generatorCommit': 'a' * 40, 'siteCommit': 'b' * 40}
        self.domains = {'deploymentMode': 'standalone', 'domains': []}
        self.pins = {'schemaVersion': 1, 'images': {'producer': self.image, 'ondemand': self.image}}
        self.write(self.bundle / 'site/manifest.json', self.manifest)
        self.write(self.bundle / 'site/pins.json', self.pins)
        self.write(self.bundle / 'stack.ir.json', self.ir)
        self.write(self.bundle / 'podman-domains.json', self.domains)
        self.provenance['manifestSha256'] = self.digest(self.bundle / 'site/manifest.json')
        self.write(self.bundle / 'source-provenance.json', self.provenance)
        self.metadata = {'backend': 'podman', 'deploymentMode': 'standalone',
                         'irSha256': self.digest(self.bundle / 'stack.ir.json'),
                         'sourceProvenanceSha256': self.digest(self.bundle / 'source-provenance.json')}
        self.write(self.bundle / 'bundle.json', self.metadata)
        (self.bundle / 'ops/package-release-images.py').write_bytes(SOURCE.with_name('package-release-images.py').read_bytes())
        self.data = {'schemaVersion': 1, 'images': [{'image': self.image,
                     'archiveFilename': self.archive.name, 'archiveSha256': self.digest(self.archive),
                     'archiveBytes': self.archive.stat().st_size}]}
        self.write(self.inputs, self.data)
        self.proof = {'schemaVersion': 1, 'purpose': 'source-bound-release-images',
            'binding': {'bundleIrSha256': self.digest(self.bundle / 'stack.ir.json'),
                        'sourceProvenanceSha256': self.digest(self.bundle / 'source-provenance.json'),
                        'siteManifestSha256': self.digest(self.bundle / 'site/manifest.json'),
                        'domainMetadataSha256': self.digest(self.bundle / 'podman-domains.json'),
                        'localBuildPinsSha256': self.digest(self.bundle / 'site/pins.json')},
            'imageAuthorities': {self.image: ['root']}, 'inputSha256': 'a' * 64,
            'inputMode': 'offline-supply',
            'packagerSha256': self.digest(self.bundle / 'ops/package-release-images.py'),
            'imageInputsSha256': self.digest(self.inputs),
            'ociProofs': {self.image: M.package_verifier().verify_oci(self.archive, self.image)},
            'activationAuthorized': False, 'acceptedIntegratedInstalls': 0}
        self.write(self.proofpath, self.proof)
        # Mock ownership metadata only; all archive/hash/OCI/CAS logic is real.
        # No chown, sudo, network, native container command or installed claim.
        real_lstat, real_fstat = Path.lstat, os.fstat
        self.owners = {}
        def metadata(info, uid=0):
            fields = {k: getattr(info, k) for k in dir(info) if k.startswith('st_')}
            fields['st_uid'] = uid
            return SimpleNamespace(**fields)
        def lstat(path):
            return metadata(real_lstat(path), self.owners.get(path, 0))
        def fstat(fd):
            info = real_fstat(fd)
            uid = 0
            for path, owner in self.owners.items():
                candidate = real_lstat(path)
                if (candidate.st_dev, candidate.st_ino) == (info.st_dev, info.st_ino):
                    uid = owner
                    break
            return metadata(info, uid)
        for target, name, value in ((Path, 'lstat', lstat), (os, 'fstat', fstat)):
            mock = patch.object(target, name, value); mock.start(); self.addCleanup(mock.stop)
        native = patch.object(M.subprocess, 'run', side_effect=AssertionError('native call forbidden'))
        self.native = native.start(); self.addCleanup(native.stop)

    @staticmethod
    def digest(path):
        return sha(path.read_bytes())

    @staticmethod
    def write(path, body):
        path.write_text(json.dumps(body)); path.chmod(0o600)

    def save_proof(self):
        self.write(self.proofpath, self.proof)

    def qualified_artifact_report(self):
        owner = SOURCE.with_name('qualified-image-supply.py')
        (self.bundle / 'ops/qualified-image-supply.py').write_bytes(owner.read_bytes())
        report = {'schemaVersion': 1, 'qualifierSha256': self.digest(owner),
                  'binding': self.proof['binding'], 'ociProofs': self.proof['ociProofs'],
                  'producerCopyClosures': {'producer': {}, 'ondemand': {}},
                  'activationAuthorized': False, 'acceptedIntegratedInstalls': 0}
        path = self.output / 'source-qualification.json'
        self.write(path, report)
        self.proof['inputMode'] = 'qualified-artifact-rebind'
        self.proof['inputSha256'] = self.digest(path)
        self.save_proof()
        return path, report

    def test_qualified_artifact_report_and_trusted_owner_required(self):
        path, report = self.qualified_artifact_report()
        rows = M.validate_standalone(self.bundle, self.inputs)
        self.assertEqual(len(rows), 1)
        self.native.assert_not_called()
        (self.bundle / 'ops/qualified-image-supply.py').write_text('changed owner')
        with self.assertRaises(ValueError): M.validate_standalone(self.bundle, self.inputs)

    def test_qualified_artifact_report_cannot_drop_ondemand_or_change_binding(self):
        path, report = self.qualified_artifact_report()
        for changes in ({'producerCopyClosures': {'producer': {}}}, {'binding': {}},
                        {'schemaVersion': True}, {'acceptedIntegratedInstalls': True},
                        {'activationAuthorized': True}, {'ociProofs': {}}):
            self.write(path, {**report, **changes})
            self.proof['inputSha256'] = self.digest(path); self.save_proof()
            with self.assertRaises(ValueError): M.validate_standalone(self.bundle, self.inputs)
        self.native.assert_not_called()

    def test_qualified_artifact_report_missing_or_nonroot_refused(self):
        path, _ = self.qualified_artifact_report()
        self.owners[path] = 1000
        with self.assertRaises(ValueError): M.validate_standalone(self.bundle, self.inputs)
        del self.owners[path]; path.unlink()
        with self.assertRaises(OSError): M.validate_standalone(self.bundle, self.inputs)

    def rebind_inputs(self):
        self.data['images'][0]['archiveSha256'] = self.digest(self.archive)
        self.data['images'][0]['archiveBytes'] = self.archive.stat().st_size
        self.write(self.inputs, self.data)
        self.proof['imageInputsSha256'] = self.digest(self.inputs); self.save_proof()

    def validate(self):
        return M.validate(self.bundle, self.inputs)

    def reject(self):
        with self.assertRaises((ValueError, OSError)):
            self.validate()
        self.native.assert_not_called()

    def test_real_oci_positive_operator_candidate_private_root_inputs(self):
        for path in self.bundle.rglob('*'):
            self.owners[path] = 1000
        self.owners[self.bundle] = 1000
        rows = self.validate()
        self.assertIsInstance(rows, list)
        self.assertEqual(rows, [(self.image, self.archive, ['root'])])
        self.assertEqual(len(self.proof['ociProofs'][self.image]['diffIds']), 2)
        rows.recheck()

    def test_missing_proof_refused(self):
        self.proofpath.unlink(); self.reject()

    def test_symlink_proof_refused(self):
        target = self.output / 'proof-target'; self.proofpath.rename(target)
        self.proofpath.symlink_to(target); self.reject()

    def test_hardlink_proof_refused(self):
        os.link(self.proofpath, self.output / 'proof-alias'); self.reject()

    def test_pending_with_valid_manifest_refused_even_dangling_link(self):
        pending = self.output / 'PENDING'
        for kind in ('file', 'link'):
            if kind == 'file': pending.write_text('pending')
            else: pending.symlink_to(self.output / 'absent')
            self.reject(); pending.unlink()

    def test_wrong_scope_never_dispatches(self):
        self.proof['imageAuthorities'][self.image] = ['unselected']
        self.save_proof(); self.reject()

    def test_proof_source_bindings_all_exact(self):
        for key in self.proof['binding']:
            old = self.proof['binding'][key]
            self.proof['binding'][key] = '0' * 64; self.save_proof(); self.reject()
            self.proof['binding'][key] = old

    def test_packager_and_input_hashes_exact(self):
        for key in ('packagerSha256', 'imageInputsSha256'):
            old = self.proof[key]; self.proof[key] = '0' * 64; self.save_proof(); self.reject()
            self.proof[key] = old

    def test_duplicate_json_and_boolean_schema_refused(self):
        for path, document in ((self.inputs, self.data), (self.proofpath, self.proof)):
            for text in ('{"schemaVersion":1,' + json.dumps(document)[1:],
                         json.dumps({**document, 'schemaVersion': True})):
                path.write_text(text); self.reject()
            self.write(path, document)

    def test_proof_not_activation_or_acceptance_token(self):
        for key, value in (('activationAuthorized', True), ('acceptedIntegratedInstalls', 1),
                           ('acceptedIntegratedInstalls', False)):
            old = self.proof[key]; self.proof[key] = value; self.save_proof(); self.reject()
            self.proof[key] = old

    def test_input_archive_and_proof_ownership_and_mode(self):
        for path in (self.inputs, self.archive, self.proofpath):
            self.owners[path] = 1000; self.reject(); self.owners[path] = 0
            path.chmod(0o666); self.reject(); path.chmod(0o600)

    def test_control_directory_and_ancestor_links_refused(self):
        self.output.chmod(0o755); self.reject(); self.output.chmod(0o700)
        self.owners[self.root] = 1000; self.reject(); self.owners[self.root] = 0
        linked = self.root / 'output-link'; linked.symlink_to(self.output, target_is_directory=True)
        with self.assertRaises(ValueError): M.validate(self.bundle, linked / self.inputs.name)
        self.native.assert_not_called()

    def test_candidate_parent_swap_to_symlink_between_check_and_open(self):
        real_ancestry = M.ancestry
        fired = False
        target = self.bundle / 'site/pins.json'
        def swap(path, private=False):
            nonlocal fired
            real_ancestry(path, private)
            if path == target and not fired:
                fired = True
                held = self.root / 'held-site'
                (self.bundle / 'site').rename(held)
                (self.bundle / 'site').symlink_to(held, target_is_directory=True)
        with patch.object(M, 'ancestry', side_effect=swap):
            self.reject()
        self.assertTrue(fired)

    def test_archive_hash_and_size_drift(self):
        self.archive.write_bytes(b'drift'); self.reject()

    def test_config_closure_cannot_be_asserted_by_proof(self):
        fixture(self.archive, corrupt=True); self.rebind_inputs(); self.reject()

    def test_wrong_config_id_even_when_archive_hash_is_bound(self):
        fixture(self.archive, diff_drift=True); self.rebind_inputs(); self.reject()

    def test_ordered_diffids_checked_against_actual_layers(self):
        fixture(self.archive, reverse=True); self.rebind_inputs(); self.reject()

    def test_diffid_assertion_drift(self):
        self.proof['ociProofs'][self.image]['diffIds'].reverse(); self.save_proof(); self.reject()

    def test_ondemand_unmanaged_build_requires_frozen_producer(self):
        self.ir['services']['ondemand'].pop('frozenBuildImage')
        self.write(self.bundle / 'stack.ir.json', self.ir)
        self.metadata['irSha256'] = self.digest(self.bundle / 'stack.ir.json')
        self.write(self.bundle / 'bundle.json', self.metadata)
        self.proof['binding']['bundleIrSha256'] = self.metadata['irSha256']; self.save_proof()
        self.reject()

    def test_ondemand_producer_pins_exact_set(self):
        self.pins['images'].pop('ondemand'); self.write(self.bundle / 'site/pins.json', self.pins)
        self.proof['binding']['localBuildPinsSha256'] = self.digest(self.bundle / 'site/pins.json')
        self.save_proof(); self.reject()

    def test_plain_standalone_install_refused(self):
        with self.assertRaises(ValueError): M.install([(self.image, self.archive, ['root'])], self.bundle)
        self.native.assert_not_called()

    def test_postvalidate_source_proof_input_archive_and_pending_CAS(self):
        paths = (self.bundle / 'stack.ir.json', self.proofpath, self.inputs, self.archive)
        for path in paths:
            rows = self.validate(); before = path.read_bytes()
            path.write_bytes(before + b' ')
            with self.assertRaises(ValueError): M.install(rows, self.bundle)
            path.write_bytes(before)
        rows = self.validate(); (self.output / 'PENDING').symlink_to(self.output / 'absent')
        with self.assertRaises(ValueError): M.install(rows, self.bundle)
        self.native.assert_not_called()

    def test_postvalidate_row_scope_and_bundle_swap_refused(self):
        rows = self.validate(); rows[0][2].append('unselected')
        with self.assertRaises(ValueError): M.install(rows, self.bundle)
        rows = self.validate()
        with self.assertRaises(ValueError): M.install(rows, self.root)
        self.native.assert_not_called()

    def test_recheck_between_inspect_and_load(self):
        rows = self.validate(); calls = []
        def run(command, **kwargs):
            calls.append(command)
            (self.output / 'PENDING').write_text('pending')
            return SimpleNamespace(returncode=1, stdout='')
        with patch.object(M.subprocess, 'run', side_effect=run):
            with self.assertRaises(ValueError): M.install(rows, self.bundle)
        self.assertEqual(len(calls), 1)
        self.assertIn('inspect', calls[0])

    def test_beforeload_open_FD_swap_refused(self):
        rows = self.validate(); calls = []
        wrong = self.root / 'wrong.tar'; wrong.write_bytes(b'not selected')
        real_open = os.open
        fired = False
        def swapped(path, flags, *args, **kwargs):
            nonlocal fired
            if Path(path).name == self.archive.name and calls and not fired:
                fired = True
                return real_open(wrong, flags, *args, **kwargs)
            return real_open(path, flags, *args, **kwargs)
        def run(command, **kwargs):
            calls.append(command); return SimpleNamespace(returncode=1, stdout='')
        with patch.object(M.subprocess, 'run', side_effect=run), patch.object(os, 'open', side_effect=swapped):
            with self.assertRaisesRegex(ValueError, 'Opened archive differs'):
                M.install(rows, self.bundle)
        self.assertTrue(fired)
        self.assertEqual(len(calls), 1)

    def test_exact_selected_root_and_rootless_stores_each_load_and_inspect(self):
        graph = self.root / 'selected-graph'; graph.mkdir(mode=0o700)
        self.owners[graph] = 3201
        self.domains['domains'] = [{'name': 'apps', 'user': 'service-apps', 'graphRoot': str(graph)}]
        self.ir['services']['ondemand'].update({'placement': 'rootless', 'rootlessDomain': 'apps'})
        self.write(self.bundle / 'stack.ir.json', self.ir)
        self.write(self.bundle / 'podman-domains.json', self.domains)
        self.metadata['irSha256'] = self.digest(self.bundle / 'stack.ir.json')
        self.write(self.bundle / 'bundle.json', self.metadata)
        self.proof['binding']['bundleIrSha256'] = self.metadata['irSha256']
        self.proof['binding']['domainMetadataSha256'] = self.digest(self.bundle / 'podman-domains.json')
        self.proof['imageAuthorities'][self.image] = ['root', 'service-apps']; self.save_proof()
        rows = self.validate(); loaded = set(); calls = []
        def run(command, **kwargs):
            calls.append(command)
            user = 'service-apps' if 'runuser' in command else 'root'
            if command[-1] == 'load':
                self.assertNotIn(str(self.archive), command)
                self.assertEqual(kwargs['stdin'].read(), self.archive.read_bytes())
                loaded.add(user)
                return SimpleNamespace(returncode=0)
            if 'exists' in command:
                return SimpleNamespace(returncode=0)
            self.assertIn('inspect', command)
            return SimpleNamespace(returncode=0 if user in loaded else 1, stdout=self.image)
        account = SimpleNamespace(pw_uid=3201, pw_dir='/synthetic/service-apps')
        with (patch.object(M.subprocess, 'run', side_effect=run),
              patch.object(M.pwd, 'getpwnam', return_value=account), contextlib.redirect_stdout(io.StringIO())):
            M.install(rows, self.bundle)
        self.assertEqual(loaded, {'root', 'service-apps'})
        self.assertEqual(sum(command[-1] == 'load' for command in calls), 2)
        self.assertTrue(any('TMPDIR=' + str(graph) in command for command in calls))

    def test_root_opened_stdin_then_exact_store_inspect(self):
        rows = self.validate(); calls = []
        def run(command, **kwargs):
            calls.append(command)
            if command[-1] == 'load':
                self.assertNotIn(str(self.archive), command)
                self.assertEqual(kwargs['stdin'].read(), self.archive.read_bytes())
                self.assertEqual(kwargs['timeout'], M.image_load_timeout(self.archive.stat().st_size))
                return SimpleNamespace(returncode=0)
            if 'exists' in command:
                return SimpleNamespace(returncode=0)
            return SimpleNamespace(returncode=1 if len(calls) == 1 else 0, stdout=self.image)
        with patch.object(M.subprocess, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            M.install(rows, self.bundle)
        self.assertEqual(calls[1], ['podman', 'load'])
        self.assertIn('inspect', calls[2])


if __name__ == '__main__':
    unittest.main()
