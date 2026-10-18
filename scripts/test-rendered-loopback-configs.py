#!/usr/bin/env python3
"""Synthetic post-render routing parity; never modifies installed artifacts."""
import json,os,shutil,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'runtime-generator/podman-ops/install-podman-bundle.sh'
@unittest.skipUnless(shutil.which('jq'),'jq required')
class RenderOnly(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory(prefix='p0-render-only-unit-');self.addCleanup(t.cleanup);self.root=Path(t.name)
  for name in ['quadlet/rootful','ops','site','runtime/configs/mas','bin']:(self.root/name).mkdir(parents=True,exist_ok=True)
  (self.root/'ops/verify-agent-vm-bundle.py').write_text('# synthetic pin checker; not a provenance test\n')
  self.put('bundle.json',{'backend':'podman'});self.put('podman-domains.json',{'schemaVersion':1,'domains':[{'name':'apps','user':'synthetic'}]})
  self.put('stack.ir.json',{'services':{'mas':{'placement':'rootless','rootlessDomain':'apps','volumes':['./configs/mas/config.yaml:/config/config.yaml:ro']}}})
  self.put('podman-loopback-endpoints.json',{'endpoints':[{'service':'postgres','containerPort':5432,'hostPort':56033,'consumers':['apps']}]})
  self.config=self.root/'runtime/configs/mas/config.yaml';self.config.write_text('database:\n  host: postgres\n  port: 5432\n  password: "private-synthetic-value"\n')
  self.env={**os.environ,'WEBSERVICES_STATE_ROOT':str(self.root/'must-not-create-state'),'WEBSERVICES_QUADLET_DIR':str(self.root/'must-not-create-units')}
  for command in ['podman','systemd-analyze','systemctl','sops']:
   file=self.root/'bin'/command;file.write_text('#!/bin/sh\nprintf invoked > "'+str(self.root/'unexpected-native-call')+'"\nexit 97\n');file.chmod(0o755)
  self.env['PATH']=str(self.root/'bin')+':'+self.env['PATH']
 def put(self,name,value):(self.root/name).write_text(json.dumps(value))
 def run_mode(self,*extra):return subprocess.run(['bash',str(SCRIPT),'--bundle',str(self.root),'--rewrite-rendered-configs',*extra],env=self.env,capture_output=True,text=True,timeout=10)
 def assert_no_installation(self):
  for name in ['must-not-create-state','must-not-create-units','unexpected-native-call']:self.assertFalse((self.root/name).exists(),name)
 def test_reapplies_split_host_port_after_template_render_without_activation(self):
  result=self.run_mode();self.assertEqual(result.returncode,0,result.stderr);text=self.config.read_text()
  self.assertIn('host: host.containers.internal',text);self.assertIn('port: 56033',text);self.assertIn('password: "private-synthetic-value"',text);self.assert_no_installation()
 def test_uri_and_consumer_scope_are_preserved(self):
  self.config.write_text('uri: postgres://user:password@postgres:5432/db\n')
  other=self.root/'runtime/configs/unowned.yaml';other.write_text('host: postgres\nport: 5432\n')
  self.assertEqual(self.run_mode().returncode,0);self.assertIn('@host.containers.internal:56033/',self.config.read_text());self.assertEqual(other.read_text(),'host: postgres\nport: 5432\n');self.assert_no_installation()
 def test_second_pass_is_idempotent(self):
  self.assertEqual(self.run_mode().returncode,0);text=self.config.read_bytes();self.assertEqual(self.run_mode().returncode,0);self.assertEqual(self.config.read_bytes(),text)
 def test_mutating_or_inspection_options_cannot_mix_with_build_only_mode(self):
  original=self.config.read_bytes()
  for options in [('--activate',),('--inspect',),('--env-dir','/unknown'),('--resume-intent','a'*64),('--retire-failed-intent','a'*64,'--reviewed-data-state')]:
   with self.subTest(options=options):self.assertEqual(self.run_mode(*options).returncode,2)
  self.assertEqual(self.config.read_bytes(),original);self.assert_no_installation()
 def test_inert_renderer_corrects_before_manifest_and_pointer_publication(self):
  source=(ROOT/'runtime-generator/podman-ops/venue-release-inert.py').read_text()
  begin=source.index('def prepare(');end=source.index('\ndef retire(',begin);prepare=source[begin:end]
  self.assertLess(prepare.index('--rewrite-rendered-configs'),prepare.index('whole=inventory(release)'));self.assertLess(prepare.index('--rewrite-rendered-configs'),prepare.index('os.symlink('))
if __name__=='__main__':unittest.main()
