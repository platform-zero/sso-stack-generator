#!/usr/bin/env python3
"""Isolated private-output/full-import fixtures, never installed identity proof."""
import importlib.util,json,os,shutil,tempfile,unittest
from pathlib import Path
R=Path(__file__).resolve().parents[1];p=R/'runtime-generator/podman-ops/prepare-owner-import.py';s=importlib.util.spec_from_file_location('prepare_owner_fixture',p);M=importlib.util.module_from_spec(s);s.loader.exec_module(M)
class PrepareOwner(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.b=Path(self.t.name)/'bundle';self.c=self.b/'runtime/configs';(self.c/'keycloak/realm').mkdir(parents=True);(self.b/'site').mkdir();(self.b/'stack.config/keycloak').mkdir(parents=True)
  self.source=R.parent/'module-delivery/keycloak/stack.config/keycloak/owner_import.py'
  shutil.copyfile(self.source,self.b/'stack.config/keycloak/owner_import.py');(self.b/'stack.config/keycloak/owner_import.py').chmod(0o600);self.manifest={'deploymentMode':'standalone','storageScope':{'root':'/not-used-fixture','dataClass':'synthetic'}};self.save_manifest()
  self.realm=self.c/'keycloak/realm/webservices-realm.json';self.realm.write_text(json.dumps({'realm':'webservices','enabled':True,'registrationAllowed':False,'duplicateEmailsAllowed':False,'clients':[]}));self.realm.chmod(0o600)
  self.subject='a12639d7-cc11-4738-8921-889bff667700';self.fields=['synthetic-new-owner',self.subject,'synthetic-owner','synthetic-owner@example.invalid','K'*48,self.subject]
 def tearDown(self):self.t.cleanup()
 def save_manifest(self):
  p=self.b/'site/manifest.json';p.write_text(json.dumps(self.manifest));p.chmod(0o600)
 def test_private_atomic_exact_subject_import(self):
  result=M.prepare(self.b,self.c,self.fields);self.assertFalse(result['credentialOutput']);self.assertNotIn(self.fields[4],json.dumps(result))
  user=json.loads(self.realm.read_text())['users'][0];self.assertEqual(user['id'],self.subject);self.assertEqual(user['credentials'][0]['value'],self.fields[4]);self.assertEqual(self.realm.stat().st_mode&0o777,0o600);self.assertEqual(self.realm.stat().st_nlink,1)
 def test_production_or_managed_refused_without_output_change(self):
  for key,value in [('deploymentMode','managed'),('dataClass','production')]:
   before=self.realm.read_bytes()
   if key=='dataClass':self.manifest['storageScope'][key]=value
   else:self.manifest[key]=value
   self.save_manifest()
   with self.assertRaises(ValueError):M.prepare(self.b,self.c,self.fields)
   self.assertEqual(self.realm.read_bytes(),before)
   self.manifest={'deploymentMode':'standalone','storageScope':{'root':'/not-used-fixture','dataClass':'synthetic'}}
 def test_existing_preserves_and_rejects_accidental_initial_password(self):
  before=self.realm.read_bytes();fields=['existing','','','','',''];M.prepare(self.b,self.c,fields);self.assertEqual(self.realm.read_bytes(),before)
  fields[4]='K'*48
  with self.assertRaises(ValueError):M.prepare(self.b,self.c,fields)
 def test_subject_mismatch_preserves_original(self):
  before=self.realm.read_bytes();self.fields[-1]='b12639d7-cc11-4738-8921-889bff667700'
  with self.assertRaises(ValueError):M.prepare(self.b,self.c,self.fields)
  self.assertEqual(self.realm.read_bytes(),before)
 def test_no_link_hardlink_or_external_output(self):
  with self.assertRaises(ValueError):M.prepare(self.b,self.b/'other',self.fields)
  target=self.realm.with_name('linked');os.link(self.realm,target)
  with self.assertRaises(ValueError):M.prepare(self.b,self.c,self.fields)
  target.unlink();self.realm.unlink();self.realm.symlink_to(self.source)
  with self.assertRaises(OSError):M.prepare(self.b,self.c,self.fields)
 def test_renderer_credentials_not_in_process_arguments_or_configure_env(self):
  body=(R/'scripts/deploy/render-runtime.sh').read_text();self.assertIn("printf '%s\\0'",body)
  args=body.split('python3 -B "$BUNDLE_ROOT/ops/prepare-owner-import.py"',1)[1].split('fi',1)[0]
  self.assertNotIn('PASSWORD',args)
  yaml=(R.parent/'module-delivery/keycloak-auth-gateway/stack.runtime.yaml').read_text();self.assertNotIn('KEYCLOAK_OWNER_INITIAL_PASSWORD:',yaml)
if __name__=='__main__':unittest.main()
