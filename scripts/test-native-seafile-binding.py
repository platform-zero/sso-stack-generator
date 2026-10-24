#!/usr/bin/env python3
"""Real temporary FD walks with synthetic UID/ACL/NSS/inactive observations.

No host actor, container, journal grant, data operation or application acceptance.
"""
import importlib.util
from pathlib import Path
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('seafile_binding_projection_fixture',HERE/'test-native-runtime-projection-owner.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
source=HERE.parent/'runtime-generator/podman-ops/native-seafile-ownership.py'
spec=importlib.util.spec_from_file_location('seafile_binding_tested',source)
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)

class Binding(unittest.TestCase):
 external=False
 def setUp(self):
  h.Owner.setUp(self)
  for row in self.rows:row['services']=[]
  image='registry.invalid/public@sha256:'+'a'*64
  base=dict(placement='rootless',lifecycle='daemon',image=image,environment={})
  self.ir['services']={
   'mariadb':dict(base,rootlessDomain='platform',volumes=['./configs/mariadb/init.sql:/init.sql:ro']),
   'valkey':dict(base,rootlessDomain='platform',volumes=[]),
   'seafile':dict(base,rootlessDomain='apps',entrypoint=['/bin/bash','/runtime-entrypoint.sh'],volumes=[
    'seafile_files:/shared',
    *['./configs/'+name+':'+target+':ro' for name,target in zip(s.IMPLEMENTATION_FILES,s.IMPLEMENTATION_TARGETS)],
    './configs/'+s.AUTH_SOURCE+':/run/seafile-admin/authorization.json:ro'])}
  for domain,names in (('platform',['mariadb','valkey']),('apps',['seafile'])):
   row=next(row for row in self.rows if row['name']==domain);row['services']=names
   state=Path(row['stateRoot']);slot=state/'releases/fresh';self.mkdir(slot)
   self.set_owner(state/'releases',row['uid'],self.accounts[row['user']].pw_gid)
   self.put(slot/'build/selected/source.sh',b'#!/bin/sh\ntrue\n')
  self.put(self.release/'runtime/stack.env',b'DOMAIN=synthetic.invalid\nFIREFLY_OWNER_SUBJECT=explicit-sub\nP0_DERIVATION_MASTER_KEY=root-master-sentinel\n')
  self.put(self.release/'runtime/configs'/h.p.IDP_REALM,h.p.encoded(dict(realm='webservices',users=[dict(id='explicit-sub',username='owner',email='owner@synthetic.invalid',enabled=True,credentials=[dict(type='password',value='model-owner-credential')])])) )
  self.put(self.release/'runtime/configs/mariadb/init.sql',b'public SQL fixture')
  for name in s.IMPLEMENTATION_FILES:self.put(self.release/'runtime/configs'/name,('public-fixture:'+name).encode())
  self.reseal()
  self.patch=patch.object(s,'projection_owner',return_value=h.o);self.patch.start()
 def binding(self):return s.PreparingBinding(self.install,self.release,self.prior)
 def test_complete_two_domain_real_fd_binding_has_no_mutation_or_admission(self):
  before=(self.install/'.install-intent.json').read_bytes();context=self.binding()
  try:
   self.assertEqual(context.identity['subject'],'explicit-sub')
   self.assertEqual(set(context.source),{'mariadb','valkey','seafile'})
   self.assertNotIn(s.AUTH_SOURCE,context.files)
   self.assertEqual(context.receipt_sha,h.p.sha(before));context.verify()
   self.assertEqual(before,(self.install/'.install-intent.json').read_bytes())
   self.assertEqual(self.mutations,[])
   self.assertFalse(any((Path(row['stateRoot'])/'releases/fresh/runtime').exists() for row in self.rows))
  finally:context.close()
 def test_caller_authorization_or_nonempty_pin_refuses(self):
  self.put(self.release/'runtime/configs'/s.AUTH_SOURCE,b'caller-generated')
  with self.assertRaises(s.Refused):self.binding()
  (self.release/'runtime/configs'/s.AUTH_SOURCE).unlink()
  path=self.release/'runtime/stack.env';self.put(path,path.read_bytes()+b'SEAFILE_ADMIN_AUTHORIZATION_SHA256='+b'a'*64+b'\n')
  with self.assertRaises(s.Refused):self.binding()
 def test_root_master_or_owner_password_never_enters_preparation_config(self):
  path=self.release/'runtime/configs/seafile/seahub_settings.py'
  for secret in (b'root-master-sentinel',b'model-owner-credential'):
   with self.subTest(kind='root' if secret.startswith(b'root') else 'owner'):
    self.put(path,secret)
    with self.assertRaises(s.Refused):self.binding()
  self.assertEqual(self.mutations,[])
 def test_second_sweep_rejects_environment_config_and_late_auth(self):
  for kind in ('environment','config','authorization'):
   with self.subTest(kind=kind):
    context=self.binding()
    path=self.release/('runtime/stack.env' if kind=='environment' else 'runtime/configs/mariadb/init.sql' if kind=='config' else 'runtime/configs/'+s.AUTH_SOURCE)
    original=path.read_bytes() if path.exists() else None
    try:
     self.put(path,(original or b'')+b'changed')
     with self.assertRaises((s.Refused,h.o.Refused,h.p.Refusal)):context.verify()
    finally:
     context.close()
     if original is None:path.unlink()
     else:self.put(path,original)
 def test_unpinned_support_image_or_wrong_service_owner_refuses(self):
  original=self.ir['services']['mariadb']['image'];self.ir['services']['mariadb']['image']='mariadb:latest';self.reseal()
  with self.assertRaises(s.Refused):self.binding()
  self.ir['services']['mariadb']['image']=original
  self.ir['services']['mariadb']['rootlessDomain']='apps';self.reseal()
  with self.assertRaises(h.o.Refused):self.binding()

# Reuse ONLY fixture utilities, never inherit/recount the other suite's tests.
for name,value in h.Owner.__dict__.items():
 if not name.startswith(('test_','__')) and name not in ('setUp','external') and callable(value):
  setattr(Binding,name,value)

if __name__=='__main__':unittest.main()
