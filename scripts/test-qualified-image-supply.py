#!/usr/bin/env python3
"""Artifact/COPY model regressions, not runtime/store/namespace qualification.

Reuse the existing disposable OCI fixtures and their ownership substitutes;
production owner/link gates are not weakened or original permissions altered.
"""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


BASE = load('_qualified_supply_fixtures', HERE / 'test-package-release-images.py')
M = load('_qualified_supply_owner', HERE.parent / 'runtime-generator/podman-ops/qualified-image-supply.py')


class CopyClosure(unittest.TestCase):
    def setUp(self):
        self.files = {name: {'sha256': str(i) * 64, 'executable': False} for i, name in enumerate(
            ('src/main.py', 'src/lib/a.py', 'src/lib/b.txt', 'unreferenced.txt'), 1)}

    def test_directory_transitive_copy(self):
        self.assertEqual(set(M.copy_closure('COPY src /app', self.files)),
                         {'src/main.py', 'src/lib/a.py', 'src/lib/b.txt'})

    def test_wildcards_do_not_cross_components(self):
        self.assertEqual(set(M.copy_closure('COPY src/*.py /app', self.files)), {'src/main.py'})

    def test_context_dot_and_multistage_transitivity(self):
        recipe = 'FROM pinned AS build\nCOPY . .\nFROM pinned\nCOPY --from=build /out/app /app\n'
        self.assertEqual(set(M.copy_closure(recipe, self.files, 'src')), set(self.files) - {'unreferenced.txt'})

    def test_copy_options_and_continuations(self):
        self.assertEqual(set(M.copy_closure('COPY --chown=${UID}:${GID} src/main.py \\\n src/lib/a.py /app', self.files)), {'src/main.py', 'src/lib/a.py'})

    def test_dynamic_escaping_remote_and_unknown_syntax_refused(self):
        for recipe in ('COPY ../source /app', 'COPY /source /app', 'COPY ${SRC} /app',
                       'COPY missing /app', 'COPY ["src/main.py", "/app"]',
                       'COPY --link src /app', 'COPY --from=external /app /app',
                       'ADD https://example.test/app /app', 'ONBUILD COPY . .',
                       'RUN --mount=type=bind,source=. cat /source', 'COPY src \\'):
            with self.subTest(recipe=recipe), self.assertRaises(ValueError):
                M.copy_closure(recipe, self.files)

    def test_ignore_file_needs_separate_review(self):
        with self.assertRaises(ValueError):
            M.copy_closure('COPY src /app', {**self.files, '.dockerignore': self.files['src/main.py']})


class ArtifactRebind(BASE.FreezeWorkflow):
    # Inherited package regressions also run with this expanded artifact fixture.
    def setUp(self):
        super().setUp()
        self.original_package = M.package
        M.package = BASE.M
        self.addCleanup(setattr, M, 'package', self.original_package)
        patch.object(M, 'protected_directory', side_effect=self.fixture_directory).start()
        patch.object(BASE.M.os, 'statvfs', return_value=SimpleNamespace(f_bavail=1024**3, f_frsize=4096)).start()
        self.old_bundle = self.root / 'original-bundle'; self.old_bundle.mkdir()
        self.public = self.root / 'public-build'; self.public.mkdir()
        build = self.bundle / 'build'; build.mkdir()
        self.recipe = 'FROM immutable\nCOPY source.py /app/source.py\n'
        for root in (build, self.public):
            (root / 'Containerfile').write_text(self.recipe)
            (root / 'source.py').write_text('synthetic source only\n')
            (root / 'ignored.txt').write_text('not in any COPY\n')
        for root in (self.bundle, self.old_bundle):
            directory = root / 'quadlet/rootless-apps'; directory.mkdir(parents=True)
            (directory / 'webservices-producer.build').write_text(
                '[Build]\nImageTag=localhost/webservices/producer:bundle\n'
                'SetWorkingDirectory="/private/current/build"\nFile=Containerfile\nPull=never\n')
        self.json(self.old_bundle / 'stack.ir.json', self.ir)
        self.record = self.root / 'producer.json'
        row = self.supply_doc['images'][0]
        source_hashes = M.tree(self.public, {})
        self.record_doc = {'outputs': {'producer': {
            **row, 'recipePath': 'Containerfile', 'recipeSha256': source_hashes['Containerfile']['sha256'],
            'ociProof': BASE.M.verify_oci(self.supply / 'image.tar', self.image)}},
            'publicBuildFiles': len(source_hashes), 'publicBuildTreeSha256': M.tree_hash(source_hashes),
            'sourceBundleIrSha256': BASE.M.digest_file(self.old_bundle / 'stack.ir.json'),
            'allSelectedRecipesQualified': True}
        self.json(self.record, self.record_doc)
        self.inputs = self.supply / 'image-inputs.json'
        self.json(self.inputs, {'schemaVersion': 1, 'images': [row]})
        self.rebound = self.root / 'new-artifacts'
        # Producer metadata cannot be an ancestor of output. Give the metadata
        # a separate protected fixture authority, just as production requires.
        records = self.root / 'records'; records.mkdir()
        self.record.rename(records / self.record.name); self.record = records / self.record.name

    def rebind(self, **changes):
        args = dict(bundle=self.bundle, source_bundle=self.old_bundle, public_build=self.public,
                    producer_record=self.record, producer_sha=BASE.M.digest_file(self.record),
                    image_inputs=self.inputs, inputs_sha=BASE.M.digest_file(self.inputs), output=self.rebound)
        args.update(changes)
        return M.rebind(**args)

    def test_rebind_changes_only_transport_binding_not_image_bytes_or_authority(self):
        result = self.rebind()
        self.assertFalse((self.rebound / 'PENDING').exists())
        supply = json.loads(Path(result['supply']).read_bytes())
        self.assertEqual(supply['binding'], self.binding)
        self.assertEqual(supply['imageAuthorities'], self.selected)
        self.assertEqual(supply['images'], self.supply_doc['images'])
        self.assertEqual(BASE.M.digest_file(self.rebound / 'image.tar'), self.supply_doc['images'][0]['archiveSha256'])
        self.assertEqual((self.rebound / 'image.tar').stat().st_nlink, 1)
        report = json.loads((self.rebound / 'source-qualification.json').read_bytes())
        self.assertFalse(report['activationAuthorized'])
        self.assertEqual(report['acceptedIntegratedInstalls'], 0)
        self.export.assert_not_called()

    def test_full_record_rebinds_only_exact_selected_closure(self):
        self.record_doc['outputs']['unselected'] = {'notReadAsAuthority': True}
        self.json(self.record, self.record_doc)
        inputs = json.loads(self.inputs.read_bytes())
        inputs['images'].append({'image': 'sha256:' + 'f' * 64,
                                 'archiveFilename': 'unselected.tar',
                                 'archiveSha256': 'a' * 64, 'archiveBytes': 42})
        self.json(self.inputs, inputs)
        result = self.rebind()
        supply = json.loads(Path(result['supply']).read_bytes())
        self.assertEqual(supply['images'], self.supply_doc['images'])
        self.assertFalse((self.rebound / 'unselected.tar').exists())
        self.export.assert_not_called()

    def test_missing_selected_producer_in_full_record_refused(self):
        self.record_doc['outputs'] = {'unselected': {}}
        self.json(self.record, self.record_doc)
        with self.assertRaises(ValueError): self.rebind()
        self.assertFalse(self.rebound.exists())

    def test_subset_still_refuses_selected_copy_change(self):
        self.record_doc['outputs']['unselected'] = {}
        self.json(self.record, self.record_doc)
        (self.bundle / 'build/source.py').write_text('changed selected source\n')
        with self.assertRaises(ValueError): self.rebind()
        self.assertFalse(self.rebound.exists())

    def test_reference_package_publishes_only_protected_controls_and_real_oci_proof(self):
        with patch.object(M.QualifiedArtifacts,'copy',side_effect=AssertionError('reference mode copied archive')):
            result=self.rebind(package_output=True,archive_source=self.supply,reference_archives=True)
        self.assertEqual({p.name for p in self.rebound.iterdir()},
            {'image-inputs.json','source-qualification.json','release-image-proof.json'})
        proof=json.loads((self.rebound/'release-image-proof.json').read_bytes())
        report=json.loads((self.rebound/'source-qualification.json').read_bytes())
        self.assertEqual(proof['inputMode'],'qualified-artifact-references')
        self.assertEqual(report['archiveReferences'],{self.image[7:]+'.oci.tar':str(self.supply/'image.tar')})
        self.assertEqual(proof['ociProofs'][self.image],BASE.M.verify_oci(self.supply/'image.tar',self.image))
        self.assertFalse(proof['activationAuthorized']);self.assertEqual(result['acceptedIntegratedInstalls'],0)
    def test_reference_mode_requires_opaque_source_and_direct_package(self):
        for changes in ({'reference_archives':True},{'reference_archives':True,'package_output':True},
                        {'reference_archives':True,'archive_source':self.supply}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):self.rebind(**changes)
        self.assertFalse(self.rebound.exists())
    def test_reference_mode_keeps_metadata_reserve_without_copying_archive_bytes(self):
        with patch.object(BASE.M.os,'statvfs',return_value=SimpleNamespace(f_bavail=50*BASE.M.GIB+16*1024**2,f_frsize=1)):
            self.rebind(package_output=True,archive_source=self.supply,reference_archives=True)
        self.assertFalse(any(p.name.endswith('.tar') for p in self.rebound.iterdir()))
    def test_reference_mode_refuses_insufficient_actual_metadata_headroom(self):
        with patch.object(BASE.M.os,'statvfs',return_value=SimpleNamespace(f_bavail=50*BASE.M.GIB,f_frsize=1)),self.assertRaises(ValueError):
            self.rebind(package_output=True,archive_source=self.supply,reference_archives=True)
        self.assertFalse(self.rebound.exists())
    def test_direct_packaging_uses_existing_packager_without_intermediate_copy(self):
        result = self.rebind(package_output=True, archive_source=self.supply)
        self.assertTrue(Path(result['imageInputs']).is_file())
        self.assertFalse((self.rebound / 'supply.json').exists())
        self.assertFalse((self.rebound / 'PENDING').exists())
        proof = json.loads((self.rebound / 'release-image-proof.json').read_bytes())
        self.assertEqual(proof['inputMode'], 'qualified-artifact-rebind')
        self.assertEqual(proof['inputSha256'], BASE.M.digest_file(self.rebound / 'source-qualification.json'))
        self.assertEqual(proof['binding'], self.binding)
        self.export.assert_not_called()

    def test_data_reader_rejects_symlinks_hardlinks_and_metadata_drift(self):
        archive = self.supply / 'image.tar'
        real = self.supply / 'real.tar'; archive.rename(real); archive.symlink_to(real)
        with self.assertRaises(OSError): self.rebind(package_output=True, archive_source=self.supply)
        archive.unlink(); real.rename(archive)
        import os
        os.link(archive, real)
        with self.assertRaises(ValueError): self.rebind(package_output=True, archive_source=self.supply)
        real.unlink()
        (self.supply / 'image-inputs.json').write_text('{}')
        with self.assertRaises(ValueError): self.rebind(package_output=True, archive_source=self.supply)
        self.assertFalse(self.rebound.exists())

    def test_data_reader_rechecks_namespace_and_closes_failed_fds(self):
        import os
        original = len(os.listdir('/proc/self/fd'))
        for _ in range(3):
            with self.assertRaises(ValueError):
                M.ArchiveData(self.supply, self.inputs.name, '0' * 64)
        self.assertEqual(len(os.listdir('/proc/self/fd')), original)
        data = M.ArchiveData(self.supply, self.inputs.name, BASE.M.digest_file(self.inputs))
        try:
            data.add('image.tar')
            (self.supply / 'PENDING').write_text('unexpected source writer')
            with self.assertRaises(ValueError): data.recheck()
        finally:
            data.close()
        self.assertEqual(len(os.listdir('/proc/self/fd')), original)

    def test_unreferenced_change_allowed_without_name_allowlist(self):
        (self.bundle / 'build/ignored.txt').write_text('changed unrelated config\n')
        self.rebind()
        report = json.loads((self.rebound / 'source-qualification.json').read_bytes())
        self.assertEqual(report['changedBuildPaths'], ['ignored.txt'])

    def test_copy_change_refused_before_output(self):
        (self.bundle / 'build/source.py').write_text('changed copied source\n')
        with self.assertRaises(ValueError): self.rebind()
        self.assertFalse(self.rebound.exists())

    def test_executable_change_refused(self):
        (self.bundle / 'build/source.py').chmod(0o755)
        with self.assertRaises(ValueError): self.rebind()
        self.assertFalse(self.rebound.exists())

    def test_recipe_or_build_options_change_refused(self):
        path = self.bundle / 'quadlet/rootless-apps/webservices-producer.build'
        path.write_text(path.read_text() + 'BuildArg=CHANGED=1\n')
        with self.assertRaises(ValueError): self.rebind()
        self.assertFalse(self.rebound.exists())

    def test_changed_original_public_tree_refused(self):
        (self.public / 'ignored.txt').write_text('changed original producer input\n')
        with self.assertRaises(ValueError): self.rebind()
        self.assertFalse(self.rebound.exists())

    def test_wrong_reviewed_hash_refused(self):
        for changes in ({'producer_sha': '0' * 64}, {'inputs_sha': '0' * 64}):
            with self.assertRaises(ValueError): self.rebind(**changes)
            self.assertFalse(self.rebound.exists())

    def test_incomplete_producer_refused(self):
        self.record_doc['allSelectedRecipesQualified'] = False
        self.json(self.record, self.record_doc)
        with self.assertRaises(ValueError): self.rebind()
        self.assertFalse(self.rebound.exists())

    def test_archive_corruption_refused(self):
        with (self.supply / 'image.tar').open('ab') as file: file.write(b'corrupt')
        with self.assertRaises(ValueError): self.rebind()
        self.assertFalse(self.rebound.exists())

    def test_producer_oci_proof_disagreement_refused(self):
        self.record_doc['outputs']['producer']['ociProof']['manifestDigest'] = 'sha256:' + '0' * 64
        self.json(self.record, self.record_doc)
        with self.assertRaises(ValueError): self.rebind()
        self.assertFalse(self.rebound.exists())

    def test_pending_original_and_disjoint_output_refused(self):
        marker = self.supply / 'PENDING'; marker.write_text('incomplete')
        with self.assertRaises(ValueError): self.rebind()
        marker.unlink()
        with self.assertRaises(ValueError): self.rebind(output=self.public / 'new')
        self.assertFalse((self.public / 'new').exists())

    def test_insufficient_actual_staging_capacity_refused_before_child(self):
        with patch.object(BASE.M.os, 'statvfs', return_value=SimpleNamespace(f_bavail=1, f_frsize=4096)):
            with self.assertRaises(ValueError): self.rebind()
        self.assertFalse(self.rebound.exists())

    def test_missing_selected_archive_refused(self):
        self.json(self.inputs, {'schemaVersion': 1, 'images': []})
        with self.assertRaises(ValueError): self.rebind()
        self.assertFalse(self.rebound.exists())

    def test_changed_nonproducer_identity_refused(self):
        old = json.loads((self.old_bundle / 'stack.ir.json').read_bytes())
        old['services']['consumer']['image'] = 'sha256:' + '0' * 64
        self.json(self.old_bundle / 'stack.ir.json', old)
        self.record_doc['sourceBundleIrSha256'] = BASE.M.digest_file(self.old_bundle / 'stack.ir.json')
        self.json(self.record, self.record_doc)
        with self.assertRaises(ValueError): self.rebind()
        self.assertFalse(self.rebound.exists())

    def test_new_copied_file_not_hidden_by_original_inventory(self):
        (self.public / 'Containerfile').write_text('FROM immutable\nCOPY . /app\n')
        (self.bundle / 'build/Containerfile').write_text('FROM immutable\nCOPY . /app\n')
        hashes = M.tree(self.public, {})
        self.record_doc['publicBuildTreeSha256'] = M.tree_hash(hashes)
        self.record_doc['outputs']['producer']['recipeSha256'] = hashes['Containerfile']['sha256']
        self.json(self.record, self.record_doc)
        (self.bundle / 'build/new.py').write_text('new copied input')
        with self.assertRaises(ValueError): self.rebind()
        self.assertFalse(self.rebound.exists())

    def test_copy_interruption_retains_pending_without_supply(self):
        original = BASE.M.assert_unchanged
        def interrupted(proof):
            if self.rebound.exists(): raise ValueError('synthetic interruption')
            return original(proof)
        with patch.object(BASE.M, 'assert_unchanged', side_effect=interrupted):
            with self.assertRaises(ValueError): self.rebind()
        self.assertTrue((self.rebound / 'PENDING').exists())
        self.assertFalse((self.rebound / 'supply.json').exists())


if __name__ == '__main__':
    unittest.main()
