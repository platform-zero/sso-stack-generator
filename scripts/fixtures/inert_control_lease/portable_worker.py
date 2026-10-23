"""Generic test worker; privileged facts remain explicit INTERNAL models."""
import ast,copy,json,os,pathlib,sys,time,unittest
from contextlib import contextmanager
from unittest.mock import patch
before_path=list(sys.path);R=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(R));group=sys.argv[1]
before_modules=dict(sys.modules);snapshots=[]
readers={name:getattr(os,name) for name in ('open','read','write','stat','fstat','lstat','unlink','replace','fsync','close')};clock=time.monotonic;bytecode=sys.dont_write_bytecode;cache_prefix=sys.pycache_prefix
def remember(module):
 values=dict(vars(module));classes=[(value,dict(vars(value))) for value in values.values() if isinstance(value,type) and getattr(value,'__module__',None)==module.__name__]
 snapshots.append((module,values,classes))
def restore():
 patch.stopall()
 for module,values,classes in reversed(snapshots):
  for cls,attributes in classes:
   for name in tuple(vars(cls)):
    if name not in attributes and name not in ('__dict__','__weakref__'):delattr(cls,name)
   for name,value in attributes.items():
    if name not in ('__dict__','__weakref__'):setattr(cls,name,value)
  vars(module).clear();vars(module).update(values)
 sys.path[:]=before_path
 for name,module in tuple(sys.modules.items()):
  file=getattr(module,'__file__','')
  if name not in before_modules and (name=='review' or file and str(file).startswith(str(R))):sys.modules.pop(name,None)
 for name,module in before_modules.items():
  if name in ('policy_fence','inert_control_lease_native','review'):sys.modules[name]=module
 assert sys.path==before_path and time.monotonic is clock and sys.dont_write_bytecode is bytecode and sys.pycache_prefix==cache_prefix
 assert all(getattr(os,name) is value for name,value in readers.items()),'test reader patch leaked'
try:
 import policy_fence as p
 remember(p)
 if group=='native':
  import test_native_lease as original
  remember(original)
  import run_late_budget as author
  import fixture_bridge
  remember(author.inp.core.fixture);remember(author.inp.data)
  fixture_bridge.apply(author)
  from independent import Independent
  from supplemental import Supplemental
  suite=author.suite(True)
  for cls in (Independent,Supplemental):
   for name in sorted(n for n in cls.__dict__ if n.startswith('test_')):suite.addTest(cls(name))
  assert suite.countTestCases()==193
  import native_fresh_tests as fresh
  for cls in (fresh.Saved,fresh.Algorithm,fresh.RealNewPolicy):
   for name in sorted(n for n in cls.__dict__ if n.startswith('test_')):suite.addTest(cls(name))
  suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(fresh.code.CodeTargetTests));expected=220
 else:
  import test_complete_policy_fence as a
  remember(a)
  if group in ('policy-104','policy-budget9'):
   import policy_legacy_bridge as bridge
   if group=='policy-104':
    suite=unittest.TestSuite()
    for name in unittest.defaultTestLoader.getTestCaseNames(a.CompleteTests):suite.addTest((bridge.Legacy if name=='test_actual_context_executes_closure_order_and_cache_refusal_branch' else a.CompleteTests)(name))
    for name in ('independent_tests','test_held_policy','test_input_tree','test_tmpfiles_quiescence','c30_fd_tests','fresh_tests','budget_tests'):suite.addTests(unittest.defaultTestLoader.loadTestsFromName(name))
    expected=104
   else:
    import review_budget_tests
    suite=unittest.defaultTestLoader.loadTestsFromModule(review_budget_tests);expected=9
  elif group=='policy-code9':
   import test_code_target
   suite=unittest.defaultTestLoader.loadTestsFromTestCase(test_code_target.CodeTargetTests);expected=9
  elif group=='policy-fresh12':
   import review_cases as old
   remember(old);original_case=old.legacy_case;identity=p.file_identity
   @contextmanager
   def exact_numeric_time_case():
    def modeled(value):
     result=identity(value);result.update(mtime_ns=1024,ctime_ns=1024,dev=1);return result
    with original_case() as world,patch.object(p,'file_identity',side_effect=modeled):yield world
   old.legacy_case=exact_numeric_time_case
   class VerifiedActual(old.ActualCodeTarget):pass
   source=ast.parse((R/'review_cases.py').read_bytes());cls=next(n for n in source.body if isinstance(n,ast.ClassDef) and n.name=='ActualCodeTarget')
   method=copy.deepcopy(next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='test_private_full_fence_and_late_code_change_before_intent'))
   callback=next(n for n in ast.walk(method) if isinstance(n,ast.FunctionDef) and n.name=='altered');callback.body[0],callback.body[1]=callback.body[1],callback.body[0]
   namespace=dict(vars(old));exec(compile(ast.fix_missing_locations(ast.Module(body=[method],type_ignores=[])),'<approved-test-instrumentation>','exec'),namespace);setattr(VerifiedActual,method.name,namespace[method.name])
   suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(old.SavedRecord),unittest.defaultTestLoader.loadTestsFromTestCase(VerifiedActual)]);expected=12
  else:raise RuntimeError('unknown test group')
 assert suite.countTestCases()==expected,(group,suite.countTestCases(),expected)
 result=unittest.TextTestRunner(verbosity=2).run(suite)
 if result.skipped or result.expectedFailures or result.unexpectedSuccesses:raise RuntimeError('no skipped/xfail cases permitted')
 summary={'group':group,'testsRun':result.testsRun,'failures':[(str(t),s) for t,s in result.failures],'errors':[(str(t),s) for t,s in result.errors],'sourceScope':'SOURCE/explicit privileged fakes + own USER IO only; no native approval'}
 (R/(group+'-RESULTS.json')).write_text(json.dumps(summary,indent=2)+'\n')
 code=not result.wasSuccessful()
finally:restore()
sys.exit(code)
