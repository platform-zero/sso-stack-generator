#!/usr/bin/env python3
"""Pure protocol/source tests, NOT Root/native/app admission or acceptance.

Pass the selected owning admin_ownership.py explicitly as --module-source.
"""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

parser=argparse.ArgumentParser(add_help=False)
parser.add_argument('--module-source',required=True)
args,remaining=parser.parse_known_args()
sys.argv=[sys.argv[0],*remaining]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path)
 value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value)
 return value
owner=load('seafile_protocol_source',Path(__file__).parents[1]/'runtime-generator/podman-ops/native-seafile-ownership.py')
contract=load('selected_seafile_contract',Path(args.module_source).resolve(strict=True))

class Protocol(unittest.TestCase):
 def setUp(self):
  self.files={key:('public-fixture:'+key).encode() for key in owner.IMPLEMENTATION_FILES}
  self.identity=dict(issuer='https://keycloak.fixture.invalid/realms/webservices',subject='explicit-immutable-sub',remote_user='explicit-immutable-sub')
  self.database=dict(host='host.containers.internal',port=25003,user='seafile',schemas=['fixture_ccnet','fixture_files','fixture_hub'])
  self.password=b'fresh-independent-synthetic-fixture-credential-only-0123456789'
  self.raw,self.marker=owner.fresh_material(contract,'a'*64,'b'*64,'synthetic',self.identity,'owner@fixture.invalid',self.database,self.files,self.password,'c'*64)
  self.auth=owner.strict(self.raw)
  self.proof={key:self.auth[key] for key in owner.PROOF_FIELDS-{'local_user','account_sha256'}}
  self.proof.update(local_user=owner.subject_key(self.identity),account_sha256='d'*64)
  self.output=owner.PROOF_PREFIX+owner.encoded(self.proof)
 def test_fresh_actual_module_protocol_and_normal_conversion(self):
  self.assertEqual(owner.native_proof(self.output,self.auth),self.proof)
  raw=owner.existing_material(contract,self.raw,self.marker,self.files,self.proof)
  normal=owner.strict(raw)
  self.assertEqual(normal['operation'],'verify-existing');self.assertEqual(normal['state_kind'],'owned-existing')
  self.assertIsNone(normal['password_sha256']);self.assertEqual(normal['expected_account_sha256'],'d'*64)
  proof=dict(self.proof,operation='verify-existing')
  self.assertEqual(owner.native_proof(owner.PROOF_PREFIX+owner.encoded(proof),normal),proof)
 def test_main_owned_schema_interoperates_without_importing_service_code(self):
  raw,marker=owner.fresh_material(owner,'a'*64,'b'*64,'synthetic',self.identity,'owner@fixture.invalid',self.database,self.files,self.password,'c'*64)
  self.assertEqual((raw,marker),(self.raw,self.marker))
  normal=owner.existing_material(owner,raw,marker,self.files,self.proof)
  implementation=b'\0'.join(self.files[name] for name in owner.IMPLEMENTATION_FILES)
  actual=contract.validate_authorization(normal,owner.sha(normal),'verify-existing',marker,implementation)
  checked=owner.validate_authorization(normal,owner.sha(normal),'verify-existing',marker,implementation)
  self.assertEqual(actual,checked)
 def test_main_and_module_schema_refuse_same_invalid_native_material(self):
  mutations=[{'version':True},{'scope_id':''},{'contact_email':'OWNER@fixture.invalid'},
   {'password_sha256':None},{'local_user':'caller-picked'},
   {'expected_account_sha256':'a'*64},{'state_kind':'adopt-existing'},
   {'database_scope':dict(self.database,port=True)},
   {'database_scope':dict(self.database,schemas=['same','same','other'])},
   {'shared_identity':dict(self.identity,issuer='http://keycloak.fixture.invalid')},
   {'shared_identity':dict(self.identity,remote_user='mutable-display-name')}]
  for mutation in mutations:
   candidate=dict(self.auth,**mutation)
   marker=owner.encoded({key:candidate[key] for key in owner.MARKER_FIELDS})
   candidate['marker_sha256']=owner.sha(marker);raw=owner.encoded(candidate)
   for validator,error in ((owner,owner.Refused),(contract,contract.Refusal)):
    with self.subTest(field=next(iter(mutation)),validator=validator.__name__),self.assertRaises(error):
     validator.validate_authorization(raw,owner.sha(raw),'create-fresh',marker,b'\0'.join(self.files[name] for name in owner.IMPLEMENTATION_FILES))
 def test_production_fresh_kind_is_explicit_not_synthetic(self):
  raw,_=owner.fresh_material(contract,'a'*64,'b'*64,'production',self.identity,'owner@fixture.invalid',self.database,self.files,self.password,'c'*64)
  self.assertEqual(owner.strict(raw)['state_kind'],'fresh-new')
 def test_each_selected_binding_mutation_refuses(self):
  for field in owner.PROOF_FIELDS-{'account_sha256'}:
   with self.subTest(field=field):
    proof=copy.deepcopy(self.proof)
    if field=='version':proof[field]=True
    elif field=='shared_identity':proof[field]['subject']='other-subject'
    else:proof[field]='wrong'
    with self.assertRaises(owner.Refused):owner.native_proof(owner.PROOF_PREFIX+owner.encoded(proof),self.auth)
 def test_native_cas_change_refuses_on_verify_existing(self):
  normal=owner.strict(owner.existing_material(contract,self.raw,self.marker,self.files,self.proof))
  proof=dict(self.proof,operation='verify-existing',account_sha256='e'*64)
  with self.assertRaises(owner.Refused):owner.native_proof(owner.PROOF_PREFIX+owner.encoded(proof),normal)
 def test_unknown_missing_duplicate_or_multiple_proofs_refuse(self):
  variants=[self.output+self.output,b'no-proof\n',owner.PROOF_PREFIX+b'{"version":1,"version":1}',owner.PROOF_PREFIX+owner.encoded(dict(self.proof,foreign=True))]
  missing=dict(self.proof);del missing['fresh_nonce'];variants.append(owner.PROOF_PREFIX+owner.encoded(missing))
  for output in variants:
   with self.subTest(size=len(output)),self.assertRaises((owner.Refused,ValueError)):
    owner.native_proof(output,self.auth)
 def test_overlong_output_refuses_without_echo(self):
  with self.assertRaises(owner.Refused) as result:owner.native_proof(b'private-sentinel'*(1024*1024),self.auth)
  self.assertNotIn('private-sentinel',str(result.exception))
 def test_normal_material_requires_structured_fresh_proof(self):
  for field in ('receipt_sha256','marker_sha256','implementation_sha256','local_user'):
   proof=dict(self.proof);proof[field]='forged'
   with self.subTest(field=field),self.assertRaises(owner.Refused):
    owner.existing_material(contract,self.raw,self.marker,self.files,proof)
 def test_implementation_all_five_and_order_byte_bound(self):
  for name in owner.IMPLEMENTATION_FILES:
   changed=dict(self.files);changed[name]+=b'changed'
   self.assertNotEqual(owner.implementation_sha(changed),owner.implementation_sha(self.files))
   del changed[name]
   with self.assertRaises(owner.Refused):owner.implementation_sha(changed)
 def test_invalid_marker_identity_schema_or_password_never_emits_material(self):
  for changes in (dict(password=b'short'),dict(password=self.password+b'\n'),dict(nonce='not-a-hash'),dict(data_class='caller-owned')):
   kw=dict(contract=contract,receipt_sha='a'*64,marker_sha='b'*64,data_class='synthetic',identity=self.identity,email='owner@fixture.invalid',database=self.database,files=self.files,password=self.password,nonce='c'*64);kw.update(changes)
   with self.subTest(changes=list(changes)),self.assertRaises(owner.Refused):owner.fresh_material(**kw)
  for identity in (dict(self.identity,remote_user='display-name'),dict(self.identity,issuer='http://issuer.invalid')):
   with self.assertRaises(contract.Refusal):
    owner.fresh_material(contract,'a'*64,'b'*64,'synthetic',identity,'owner@fixture.invalid',self.database,self.files,self.password,'c'*64)

class CarriedProtocol(unittest.TestCase):
 """Pure format conversion only; no selected previous release/native authority."""
 def setUp(self):
  Protocol.setUp(self)
  self.origin=owner.encoded(dict(schemaVersion=1,phase='preparing',steps=['preparing'],previousRelease=None,inputs={'synthetic':'source-only-origin'}))
  raw,marker=owner.fresh_material(owner,owner.sha(self.origin),'b'*64,'synthetic',self.identity,'owner@fixture.invalid',self.database,self.files,self.password,'c'*64)
  auth=owner.strict(raw);proof={key:auth[key] for key in owner.PROOF_FIELDS-{'local_user','account_sha256'}}
  proof.update(local_user=owner.subject_key(self.identity),account_sha256='d'*64)
  normal=owner.existing_material(owner,raw,marker,self.files,proof)
  environment=b'SEAFILE_ADMIN_AUTHORIZATION_SHA256='+owner.sha(normal).encode()+b'\n'
  prior=dict(schemaVersion=1,module='seafile',status='completed',nativeTemporaryStop=True,
   authorizationSha256=owner.sha(normal),derivedEnvironmentSha256=owner.sha(environment),
   preparationReceiptSha256=owner.sha(self.origin),implementationSha256=owner.implementation_sha(self.files),
   scopeMarkerSha256='b'*64,existingReadback=dict(proof,operation='verify-existing'))
  self.kw=dict(normal_raw=normal,origin_snapshot=self.origin,prior_ownership=prior,prior_environment=environment,
   prior_files=self.files,marker_sha='b'*64,identity=self.identity,email='owner@fixture.invalid',database=self.database,current_files=self.files)
  self.original_marker=marker
 def test_byte_identical_carry_and_reviewed_implementation_rebind_preserve_native_cas(self):
  for files in (self.files,dict(self.files,**{owner.IMPLEMENTATION_FILES[0]:b'reviewed-new-implementation'})):
   raw,marker=owner.carried_material(**dict(self.kw,current_files=files));auth=owner.strict(raw)
   self.assertEqual(marker,self.original_marker);self.assertIsNone(auth['password_sha256'])
   self.assertEqual(auth['expected_account_sha256'],'d'*64)
   self.assertEqual(auth['local_user'],owner.subject_key(self.identity))
   self.assertEqual(auth['receipt_sha256'],owner.sha(self.origin))
   contract.validate_authorization(raw,owner.sha(raw),'verify-existing',marker,b'\0'.join(files[n] for n in owner.IMPLEMENTATION_FILES))
 def test_chained_origin_is_original_not_previous_preparation(self):
  prior=dict(self.kw['prior_ownership'],preparationReceiptSha256='e'*64,ownershipOriginReceiptSha256=owner.sha(self.origin))
  self.assertEqual(owner.carried_material(**dict(self.kw,prior_ownership=prior))[0],self.kw['normal_raw'])
  prior['ownershipOriginReceiptSha256']='f'*64
  with self.assertRaises(owner.Refused):owner.carried_material(**dict(self.kw,prior_ownership=prior))
 def test_scope_subject_contact_and_database_drift_refuse(self):
  for changes in (dict(marker_sha='e'*64),dict(identity=dict(self.identity,subject='foreign')),dict(email='other@fixture.invalid'),dict(database=dict(self.database,port=3306))):
   with self.subTest(field=next(iter(changes))),self.assertRaises(owner.Refused):owner.carried_material(**dict(self.kw,**changes))
 def test_failed_unstopped_wrong_schema_or_foreign_provenance_refuse(self):
  for changes in (dict(status='failed'),dict(nativeTemporaryStop=False),dict(schemaVersion=True),dict(module='other'),dict(authorizationSha256='e'*64),dict(derivedEnvironmentSha256='e'*64),dict(implementationSha256='e'*64),dict(scopeMarkerSha256='e'*64),dict(preparationReceiptSha256='e'*64)):
   with self.subTest(field=next(iter(changes))),self.assertRaises(owner.Refused):owner.carried_material(**dict(self.kw,prior_ownership=dict(self.kw['prior_ownership'],**changes)))
 def test_changed_account_cas_or_readback_implementation_refuse(self):
  for changes in (dict(account_sha256='e'*64),dict(implementation_sha256='e'*64),dict(operation='create-fresh'),dict(version=True)):
   prior=copy.deepcopy(self.kw['prior_ownership']);prior['existingReadback'].update(changes)
   with self.subTest(field=next(iter(changes))),self.assertRaises(owner.Refused):owner.carried_material(**dict(self.kw,prior_ownership=prior))
 def test_missing_or_changed_old_new_implementation_refuse(self):
  for which in ('prior_files','current_files'):
   for name in owner.IMPLEMENTATION_FILES:
    files=dict(self.files);del files[name]
    with self.subTest(which=which,name=name),self.assertRaises(owner.Refused):owner.carried_material(**dict(self.kw,**{which:files}))
  files=dict(self.files);files[owner.IMPLEMENTATION_FILES[0]]+=b'caller-change'
  with self.assertRaises(owner.Refused):owner.carried_material(**dict(self.kw,prior_files=files))
 def test_origin_bytes_and_environment_bytes_are_not_replaceable(self):
  for changes in (dict(origin_snapshot=self.origin+b' '),dict(prior_environment=self.kw['prior_environment']+b'changed')):
   with self.subTest(field=next(iter(changes))),self.assertRaises(owner.Refused):owner.carried_material(**dict(self.kw,**changes))
 def test_nonfresh_original_snapshot_never_becomes_adoption(self):
  for changes in (dict(schemaVersion=True),dict(phase='failed'),dict(previousRelease='/unissued'),dict(steps=['preparing','active']),dict(inputs={}),dict(nativeSeafileOwnership={'status':'completed'})):
   origin=owner.encoded(dict(owner.strict(self.origin),**changes))
   with self.subTest(field=next(iter(changes))),self.assertRaises(owner.Refused):owner.carried_material(**dict(self.kw,origin_snapshot=origin))

class ExplicitIdentity(unittest.TestCase):
 def setUp(self):
  self.values=dict(DOMAIN='fixture.invalid',KEYCLOAK_OWNER_SUBJECT='explicit-sub',FIREFLY_OWNER_SUBJECT='explicit-sub',KEYCLOAK_OWNER_USERNAME='owner',KEYCLOAK_OWNER_EMAIL='owner@fixture.invalid')
  self.realm=dict(realm='webservices',users=[dict(id='explicit-sub',username='owner',email='owner@fixture.invalid',enabled=True,requiredActions=[])])
 def test_explicit_subject_is_authority_not_contact_or_first_user(self):
  identity,email=owner.explicit_owner(self.values,self.realm)
  self.assertEqual(identity['subject'],'explicit-sub');self.assertEqual(identity['remote_user'],'explicit-sub')
  self.assertEqual(email,'owner@fixture.invalid')
  values=dict(self.values);del values['KEYCLOAK_OWNER_SUBJECT'];del values['FIREFLY_OWNER_SUBJECT']
  with self.assertRaises(owner.Refused):owner.explicit_owner(values,self.realm)
 def test_foreign_duplicate_disabled_onboarding_and_changed_contact_refuse(self):
  mutations=[dict(id='foreign'),dict(enabled=False),dict(requiredActions=['UPDATE_PASSWORD']),dict(username='other'),dict(email='changed@fixture.invalid')]
  for mutation in mutations:
   realm=copy.deepcopy(self.realm);realm['users'][0].update(mutation)
   with self.subTest(mutation=list(mutation)),self.assertRaises(owner.Refused):owner.explicit_owner(self.values,realm)
  realm=copy.deepcopy(self.realm);realm['users']*=2
  with self.assertRaises(owner.Refused):owner.explicit_owner(self.values,realm)
 def test_mismatched_explicit_finance_subject_and_issuer_refuse(self):
  for changes in (dict(FIREFLY_OWNER_SUBJECT='other'),dict(DOMAIN='bad/issuer'),dict(DOMAIN='')):
   values=dict(self.values,**changes)
   with self.subTest(changes=list(changes)),self.assertRaises(owner.Refused):owner.explicit_owner(values,self.realm)
 def test_schema_scope_order_and_port(self):
  env=dict(SEAFILE_MYSQL_DB_HOST='host.containers.internal',SEAFILE_MYSQL_DB_PORT='25003',SEAFILE_MYSQL_DB_USER='seafile',SEAFILE_MYSQL_DB_CCNET_DB_NAME='ccnet',SEAFILE_MYSQL_DB_SEAFILE_DB_NAME='files',SEAFILE_MYSQL_DB_SEAHUB_DB_NAME='hub')
  self.assertEqual(owner.database_scope(env)['schemas'],['ccnet','files','hub'])
  for value in ('0','65536','bad','-1'):
   with self.subTest(port=value),self.assertRaises(owner.Refused):owner.database_scope(dict(env,SEAFILE_MYSQL_DB_PORT=value))

class BindingRefusals(unittest.TestCase):
 def test_missing_live_root_authority_cannot_write_or_admit(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);release=root/'releases'/'unissued'
   with self.assertRaises(Exception):
    owner.PreparingBinding(root,release,dict(schemaVersion=1,phase='preparing',release=str(release)))
   self.assertEqual(list(root.iterdir()),[])
 def test_replay_records_cannot_enter_source_binding(self):
  for key in ('domainRuntimeProjections','nativeSeafileOwnership','nativeSeafilePreparation'):
   session=mock.Mock(side_effect=AssertionError('Session must not be entered'))
   with self.subTest(key=key),mock.patch.object(owner,'projection_owner',return_value=types.SimpleNamespace(Session=session)):
    with self.assertRaises(owner.Refused):owner.PreparingBinding(Path('/unissued'),Path('/unissued/releases/new'),{key:{'status':'caller'}})
    session.assert_not_called()

if __name__=='__main__':unittest.main()
