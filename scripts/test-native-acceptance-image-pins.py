#!/usr/bin/env python3
"""Actual owning Kotlin input validator + source wiring; no images/network/apps."""
import copy
import json
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'runtime-generator/stack-generator.main.kts'
RELATIVE = 'global.settings/native-retained-acceptance-image.json'

def valid():
    return {'schemaVersion':1,'purpose':'optional native retained-acceptance tooling; no managed runtime service',
            'image':'sha256:'+'1'*64,'platform':'linux/amd64','archiveFilename':'native-tool.tar',
            'archiveSha256':'2'*64,'archiveBytes':4196316672,'containerfileSha256':'3'*64,
            'sourceModule':{'id':'test-runners','git':'https://github.com/example/test-runners.git','commit':'4'*40},
            'immutableParents':[{'sourceReference':'example/java:21','immutableReference':'example/java@sha256:'+'5'*64,'imageConfigId':'6'*64},
                                {'sourceReference':'example/browser:1','immutableReference':'example/browser@sha256:'+'7'*64,'imageConfigId':'sha256:'+'8'*64}]}

class NativeAcceptancePins(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='native-acceptance-pins-source-')
        work = Path(cls.temp.name);text=SOURCE.read_text()
        begin=text.index('fun nativeAcceptanceImagePins(');end=text.index('\nfun sourceProvenance(',begin)
        function=text[begin:end]
        cases={}
        def add(name,change=None,*,body=None,relative=RELATIVE,symlink=False,absent=False):
            site=work/name;site.mkdir();(site/'global.settings').mkdir()
            node=valid()
            if change:change(node)
            pin=site/RELATIVE
            pin.write_text(body if body is not None else json.dumps(node))
            if symlink:
                other=site/'actual.json';pin.rename(other);pin.symlink_to(other)
            manifest=site/'manifest.json';manifest.write_text(json.dumps({} if absent else {'nativeAcceptanceImagePinsPath':relative}))
            cases[name]=str(manifest)
        add('valid');add('absent',absent=True)
        add('overflow_version',lambda n:n.update(schemaVersion=2**32+1))
        add('numeric_archive_digest',lambda n:n.update(archiveSha256=int('2'*64)))
        add('numeric_recipe_digest',lambda n:n.update(containerfileSha256=int('3'*64)))
        add('numeric_commit',lambda n:n['sourceModule'].update(commit=int('4'*40)))
        add('numeric_parent_config',lambda n:n['immutableParents'][0].update(imageConfigId=int('6'*64)))
        add('mutable_image',lambda n:n.update(image='example/tool:latest'))
        add('extra_field',lambda n:n.update(host_checked=True))
        add('bool_size',lambda n:n.update(archiveBytes=True))
        add('huge_size',lambda n:n.update(archiveBytes=2**63))
        add('negative_size',lambda n:n.update(archiveBytes=-1))
        add('path_archive',lambda n:n.update(archiveFilename='../tool.tar'))
        add('mutable_parent',lambda n:n['immutableParents'][0].update(immutableReference='example/java:21'))
        add('duplicate_parent',lambda n:n['immutableParents'].__setitem__(1,copy.deepcopy(n['immutableParents'][0])))
        add('credential_origin',lambda n:n['sourceModule'].update(git='https://user:pass@github.com/example/repo.git'))
        add('wrong_platform',lambda n:n.update(platform='linux/arm64'))
        add('unknown_source',lambda n:n['sourceModule'].update(id='foreign'))
        add('symlink',symlink=True)
        add('wrong_path',relative='./'+RELATIVE)
        add('oversized',body=' '*32769+json.dumps(valid()))
        add('duplicate_key',body=json.dumps(valid())[:-1]+',"schemaVersion":1}')
        harness=work/'input-validator.main.kts'
        harness.write_text('''import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.databind.JsonNode
import java.nio.file.Path
import java.nio.file.Files
import kotlin.io.path.*
val json = ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
fun fail(message: String): Nothing = error(message)
fun readTree(path: Path): ObjectNode = json.readTree(path.toFile()) as ObjectNode
'''+function+'''
val paths = json.readTree(Path(args[0]).toFile())
val results = json.createObjectNode()
paths.fields().forEachRemaining { entry ->
  val passed = try { nativeAcceptanceImagePins(Path(entry.value.asText())); true } catch (_: Exception) { false }
  results.put(entry.key, passed)
}
println(json.writeValueAsString(results))
''')
        casefile=work/'cases.json';casefile.write_text(json.dumps(cases))
        subprocess.run([str(ROOT/'gradlew'),'-p',str(ROOT),'-q',':runtime-generator:prepareGenerator'],check=True,timeout=180)
        classpath=(ROOT/'runtime-generator/build/generator-classpath.txt').read_text().strip()
        run=subprocess.run(['java','-Xmx2g','-cp',classpath,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-script',str(harness),'-no-stdlib','-no-reflect','-classpath',classpath,'--',str(casefile)],capture_output=True,text=True,timeout=180)
        if run.returncode:raise AssertionError('owning Kotlin validator did not compile/run: '+run.stderr[-4000:])
        cls.results=json.loads(run.stdout)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def test_valid_immutable_optional_pin(self):self.assertTrue(self.results['valid'])
    def test_absence_is_backward_compatible(self):self.assertTrue(self.results['absent'])
    def test_overflow_version_refused(self):self.assertFalse(self.results['overflow_version'])
    def test_numeric_archive_digest_refused(self):self.assertFalse(self.results['numeric_archive_digest'])
    def test_numeric_recipe_digest_refused(self):self.assertFalse(self.results['numeric_recipe_digest'])
    def test_numeric_commit_refused(self):self.assertFalse(self.results['numeric_commit'])
    def test_numeric_parent_config_refused(self):self.assertFalse(self.results['numeric_parent_config'])
    def test_mutable_image_refused(self):self.assertFalse(self.results['mutable_image'])
    def test_unknown_fields_refused(self):self.assertFalse(self.results['extra_field'])
    def test_boolean_size_refused(self):self.assertFalse(self.results['bool_size'])
    def test_overflow_size_refused(self):self.assertFalse(self.results['huge_size'])
    def test_negative_size_refused(self):self.assertFalse(self.results['negative_size'])
    def test_archive_path_refused(self):self.assertFalse(self.results['path_archive'])
    def test_mutable_parent_refused(self):self.assertFalse(self.results['mutable_parent'])
    def test_duplicate_parent_refused(self):self.assertFalse(self.results['duplicate_parent'])
    def test_credential_origin_refused(self):self.assertFalse(self.results['credential_origin'])
    def test_wrong_platform_refused(self):self.assertFalse(self.results['wrong_platform'])
    def test_unrelated_source_refused(self):self.assertFalse(self.results['unknown_source'])
    def test_symlink_refused(self):self.assertFalse(self.results['symlink'])
    def test_noncanonical_reference_refused(self):self.assertFalse(self.results['wrong_path'])
    def test_oversized_input_refused(self):self.assertFalse(self.results['oversized'])
    def test_duplicate_json_keys_refused(self):self.assertFalse(self.results['duplicate_key'])
    def test_materializer_declares_validated_input(self):
        text=SOURCE.read_text().split('fun materializeSiteManifest(',1)[1].split('\nfun runtimeModelService(',1)[0]
        self.assertIn('nativeAcceptanceImagePins(manifestPath)',text)
        self.assertIn('"nativeAcceptanceImagePinsPath".takeIf { manifest.has(it) }',text)
    def test_provenance_binds_source_recipe_and_lock_bytes(self):
        text=SOURCE.read_text().split('fun sourceProvenance(',1)[1].split('\nfun buildIr(',1)[0]
        self.assertIn('nativeAcceptanceImagePinsSha256',text)
        self.assertIn('module.commit != pins.path("sourceModule").path("commit").asText()',text)
        self.assertIn('stack.containers/test-runner/Containerfile',text)

class NativeAcceptanceCopiedInput(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='native-acceptance-copy-source-')
        root=Path(self.temp.name);self.site=root/'source';self.bundle=root/'bundle'
        self.source=self.site/RELATIVE;self.copy=self.bundle/'site'/RELATIVE
        for p in (self.source,self.copy):p.parent.mkdir(parents=True);p.write_text(json.dumps(valid()))
        self.manifest={'nativeAcceptanceImagePinsPath':RELATIVE}
        self.provenance={'nativeAcceptanceImagePinsSha256':hashlib.sha256(self.source.read_bytes()).hexdigest()}
        spec=importlib.util.spec_from_file_location('native_pins_source_verifier',ROOT/'scripts/verify-podman-source.py')
        self.verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.verifier)
    def tearDown(self):self.temp.cleanup()
    def check(self):return self.verifier.verify_native_acceptance_image_pins(self.bundle,self.site,self.manifest,self.provenance)
    def reject(self):
        with self.assertRaises(ValueError):self.check()
    def test_exact_source_and_bundled_bytes(self):self.check()
    def test_optional_absence_preserved(self):self.manifest={};self.provenance={};self.check()
    def test_unreferenced_provenance_refused(self):self.manifest={};self.reject()
    def test_missing_provenance_refused(self):self.provenance={};self.reject()
    def test_noncanonical_path_refused(self):self.manifest['nativeAcceptanceImagePinsPath']='./'+RELATIVE;self.reject()
    def test_source_tamper_refused(self):self.source.write_text('{}');self.reject()
    def test_bundle_tamper_refused(self):self.copy.write_text('{}');self.reject()
    def test_missing_copy_refused(self):self.copy.unlink();self.reject()
    def test_source_symlink_refused(self):self.source.unlink();self.source.symlink_to(self.copy);self.reject()
    def test_copy_symlink_refused(self):self.copy.unlink();self.copy.symlink_to(self.source);self.reject()
    def test_parent_symlink_refused(self):
        parent=self.copy.parent;other=parent.with_name('linked');parent.rename(other);parent.symlink_to(other);self.reject()
    def test_oversized_copy_refused(self):self.copy.write_bytes(b' '*32769);self.reject()

if __name__=='__main__':unittest.main()
