"""SOURCE fakes only. 45 unchanged producer test bodies + original C28 probes
with valid-facts setup overrides. The obsolete positive wire fixture is retained
in legacy, replaced by literal fc98 AST on coherent held inputs here.
"""
import ast,copy,importlib.util,json,stat,sys,types,unittest
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).resolve().parent;sys.path.insert(0,str(R))
import inert_control_lease_native as m
import test_native_lease as original
import test_dispatch_contract as dispatch
import fixture_correction as fixture
fixture.apply()
import regression_cases as regressions
Review=regressions.Review;ActualUser=regressions.ActualUser;normal_setup=Review.setUp
SKETCH={'schemaVersion','phase','namespace','hostContextSha256','provenanceSha256','planSha256','operationSha256','sourceClosureSha256'}
def review_setup(test):
 normal_setup(test)
 if test._testMethodName=='r_missing_complete_fence_fields_should_refuse':
  state=test.data();state[m.FENCE]={k:v for k,v in state[m.FENCE].items() if k in SKETCH};test.fs.nodes[test.ledger].data=m.encoded(state)
Review.setUp=review_setup
class Corrected(original.NativeTests):
 def refuse(self,fn):
  self.mutate(fn)
  with self.assertRaises(m.Refused):self.run_api()
  self.assertEqual(self.events('unlink'),[]);self.assertEqual(self.events('rmdir'),[])
 def c_literal_fc98_ten_key_closure_real_current_success(self):
  source=ast.parse((R/'policy_fence.py').read_bytes())
  function=next(n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='actual_context')
  expr=ast.Expression(next(n for n in function.body if isinstance(n,ast.Return)).value.elts[-1]);ast.fix_missing_locations(expr)
  env={'ops_sha':self.closure['ops'],'slot_sha':self.closure['slot'],'quadlet_sha':self.closure['quadlet'],
   'site_sha':self.closure['site'],'build_sha':self.closure['build'],
   'authority':{'imageIds':self.images,'frozenRegistrySha256':self.closure['frozenRegistrySha256']},
   'sha':m.digest,'protected_file':lambda p,*args:self.fs.nodes[str(p)].data,'bundle':original.P(self.bundle),
   'slot':original.P(self.slot),'slot_manifest':self.closure['manifest'],'str':str}
  wire=eval(compile(expr,'<frozen-fc98-ten-key-wire>','eval'),{'__builtins__':{}},env)
  self.assertEqual(wire,self.closure);self.assertEqual(len(wire),10)
  self.run_api();self.assertGreater(len(self.current_calls),1)
  self.assertTrue(any(not x['runtimePresent'] for x in self.current_calls))
 def c_execute_new_flat_not_original_target(self):
  self.run_api();self.assertTrue(self.loaded);self.assertTrue(all(p.startswith(self.flat+'/') for p in self.loaded))
  cfg=json.loads(self.fs.nodes[self.flat+'/SOURCE-LOCK.json'].data)
  self.assertNotEqual(cfg['codeAuthority']['ops'],cfg['targetAuthority']['ops'])
 def c_original_target_commit_not_new_g768(self):
  body=json.loads(self.fs.nodes[self.bundle+'/source-provenance.json'].data);body['generatorCommit']=fixture.PROFILE['codeAuthority']['generatorCommit']
  raw=m.encoded(body);self.fs.nodes[self.bundle+'/source-provenance.json'].data=raw;self.provenance=m.digest(raw)
  with self.assertRaisesRegex(m.Refused,'original-target-provenance'):self.run_api()
  self.assertEqual(self.loaded,[])
 def c_original_target_ops_mutation_before_import(self):
  self.fs.nodes[self.bundle+'/ops/venue-owned-stage.py'].data=b'PUBLIC wrong original code'
  with self.assertRaisesRegex(m.Refused,'original-target-ops-pins'):self.run_api()
  self.assertEqual(self.loaded,[])
 def c_flat_extra_cache_before_import(self):
  self.fs.put(self.flat+'/__pycache__/bad.pyc',data=b'PUBLIC')
  with self.assertRaises(m.Refused):self.run_api()
  self.assertEqual(self.loaded,[])
 def c_build_late_mutation_held(self):
  def callback(event):
   if event==('fsync','/audit') and self.data().get(m.KEY,{}).get('phase')=='lease-delete-issued':self.fs.nodes[self.bundle+'/build/public-build-input'].data=b'PUBLIC changed build'
  self.fs.callback=callback
  with self.assertRaises(m.Refused):self.run_api()
  self.assertEqual(self.events('unlink'),[])
 def c_site_late_mutation_held(self):
  def callback(event):
   if event==('fsync','/audit') and self.data().get(m.KEY,{}).get('phase')=='lease-delete-issued':self.fs.nodes[self.bundle+'/site/agent-vm.json'].data=b'PUBLIC changed site'
  self.fs.callback=callback
  with self.assertRaises(m.Refused):self.run_api()
  self.assertEqual(self.events('unlink'),[])
 def c_saved_policy_mode(self):self.refuse(lambda s:s[m.FENCE]['policies'][0].update(mode=0o600))
 def c_saved_policy_body(self):self.refuse(lambda s:s[m.FENCE]['policies'][1].update(bodySha256='a'*64))
 def c_saved_policy_file_id(self):self.refuse(lambda s:s[m.FENCE]['policies'][0]['file'].update(ino=True))
 def c_saved_policy_parent(self):self.refuse(lambda s:s[m.FENCE]['policies'][0]['parent'].update(ino=999999))
 def c_saved_lease_full_timestamps(self):self.refuse(lambda s:s[m.FENCE]['leaseIdentity']['file'].update(ctime_ns=999))
 def c_saved_lease_wrong_original_uid(self):self.refuse(lambda s:s[m.FENCE]['leaseIdentity']['file'].update(uid=1000))
 def c_policy_before_sha(self):self.refuse(lambda s:s[m.FENCE].update(ledgerSha256Before='f'*64))
 def c_six_epoch_chain_not_arbitrary_hashes(self):self.refuse(lambda s:s[m.FENCE].update(intendedEpochs=[str(i)*64 for i in range(1,7)],ledgerSha256Before='1'*64))
 def c_host_identity_complete(self):self.refuse(lambda s:s['venueHostUnitsRetirement']['identities'].pop(next(iter(s['venueHostUnitsRetirement']['identities']))))
 def c_controller_source_pin(self):
  self.fs.nodes[self.slot+'/p0_host_context.py'].data=b'PUBLIC unreviewed module'
  with self.assertRaises(m.Refused):self.run_api()
  self.assertEqual(self.current_calls,[])
 def c_context_current_manifest_metadata_really_checked(self):
  self.fs.nodes[self.slot+'/manifest.json'].uid=1000
  with self.assertRaises(m.Refused):self.run_api()
  self.assertEqual(self.events('unlink'),[])
 def c_initial_user_namespace_mismatch(self):
  old=self.fs.stat
  def observed(p,*a,**kw):
   if str(p)=='/proc/1/ns/user':return types.SimpleNamespace(st_dev=9,st_ino=101)
   return old(p,*a,**kw)
  with patch.object(self.fs,'stat',observed),self.assertRaises(m.Refused):self.run_api()
  self.assertEqual(self.loaded,[])
 def c_egid_refuses_before_private_reads(self):
  self.fs.egid=1000
  with self.assertRaisesRegex(m.Refused,'root-admission'):self.run_api()
  self.assertEqual(self.fs.opens,[])
 def c_real_current_fresh_bind_after_absent_directory_and_retired(self):
  self.fs.callback=lambda e:(_ for _ in ()).throw(OSError('PUBLIC crash')) if e[0]=='rmdir' else None
  with self.assertRaises(m.Refused):self.run_api()
  self.fs.callback=None;self.current_calls.clear();self.run_api();self.run_api()
  self.assertTrue(any(x=={'runtimePresent':False,'phase':'directory-delete-issued'} for x in self.current_calls))
  self.assertTrue(any(x=={'runtimePresent':False,'phase':'retired'} for x in self.current_calls))
  self.assertEqual(len(self.events('unlink')),1);self.assertEqual(len(self.events('rmdir')),1)
  self.assertFalse(any(p.startswith(self.runtime) and flags&original.os.O_CREAT for p,flags in self.fs.opens))
 def c_fence_record_and_nine_field_history_unchanged(self):
  h,v=self.history();self.mutate(lambda s:s.update(venueRegistryFailedPendingRetirement=h,venueRegistryPlan=self.images,venueRegistryVerified=v,venueRegistryPreparationAbandoned=True))
  before=copy.deepcopy(self.data()[m.FENCE]);self.run_api()
  self.assertEqual(self.data()[m.FENCE],before);self.assertEqual(self.data()['venueRegistryFailedPendingRetirement'],h)

if __name__=='__main__':
 suite=unittest.TestSuite();suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(original));suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(dispatch));suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(ActualUser))
 for name in sorted(n for n in dir(Review) if n.startswith('r_') and n!='r_complete_fc98_closure_should_interoperate'):suite.addTest(Review(name))
 for name in sorted(n for n in dir(Corrected) if n.startswith('c_')):suite.addTest(Corrected(name))
 result=unittest.TextTestRunner(verbosity=2).run(suite)
 (R/'CORRECTED-RESULTS.json').write_text(json.dumps({'testsRun':result.testsRun,'failures':[str(t) for t,_ in result.failures],'errors':[str(t) for t,_ in result.errors],'skipped':result.skipped,'scope':'SOURCE/fakes ONLY; fc98 frozen wire; settled R3 policy47 bound; C30 independent verdict pending'},indent=2)+'\n')
 sys.exit(bool(result.failures or result.errors))
