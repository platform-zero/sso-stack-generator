"""C44 test-only expansion. Original193 assertion/source bodies unchanged.
Full public57 CODE, original public57 + generated10 DATA and strict schema2.
Real new C42 validator/context run; only internal kernel/stage observations fake.
"""
import contextlib,copy,json,os,stat,types
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).resolve().parent;S=R

def apply(author):
 if getattr(author,'_portable_bridge_applied',False):return
 author._portable_bridge_applied=True
 core=author.inp.core;fixture=core.fixture;m=core.m;original=core.original
 old_setup=original.NativeTests.setUp
 @contextlib.contextmanager
 def scandir(fs,path):
  directory=fs.fds[path][0].name if type(path) is int else str(path)
  yield iter(types.SimpleNamespace(name=n) for n in fs.children(directory))
 fixture.MetadataFS.scandir=scandir
 def setup(test):
  old_setup(test);fs=test.fs;fs.path=types.SimpleNamespace(normpath=os.path.normpath)
  lock=json.loads(fs.nodes[test.flat+'/SOURCE-LOCK.json'].data)
  for name in lock['codeAuthority']['ops']:
   fs.nodes[test.flat+'/'+name].data=(R/'generator/code57'/name).read_bytes()
  lock['codeAuthority']['ops']={n:m.digest(fs.nodes[test.flat+'/'+n].data) for n in lock['codeAuthority']['ops']}
  lock.pop('ops',None)
  for name in lock['targetAuthority']['ops']:
   fs.nodes[test.bundle+'/ops/'+name].data=(R/'generator/target57'/name).read_bytes()
  lock['targetAuthority']['ops']={n:m.digest(fs.nodes[test.bundle+'/ops/'+n].data) for n in lock['targetAuthority']['ops']}
  fs.nodes[test.flat+'/retire-failed-venue-registry-image.py'].data=(R/'generator/retire-failed-venue-registry-image.py').read_bytes()
  test.ec4=m.digest(fs.nodes[test.flat+'/retire-failed-venue-registry-image.py'].data);lock['ec4']=test.ec4
  test.closure['ops']=m.digest(m.encoded(fixture.tree(test,test.bundle+'/ops')))
  state=test.data();state[m.FENCE]['sourceClosureSha256']=m.digest(m.canonical(test.closure))
  fixture.rechain(state);fs.nodes[test.ledger].data=m.encoded(state)
  cfg=lock['targetAuthority']['inputConfiguration'];cfg['initialReviewedLedgerSha256']=m.digest(fs.nodes[test.ledger].data)
  cfg['ops']={n:{'sha256':h,'mode':stat.S_IMODE(fs.nodes[test.bundle+'/ops/'+n].mode)} for n,h in fixture.tree(test,test.bundle+'/ops').items()}
  fs.nodes[test.flat+'/SOURCE-LOCK.json'].data=m.encoded(lock);fs.nodes[test.flat+'/SOURCE-LOCK.json'].mode=stat.S_IFREG|0o600
 def load(test,p,name):
  test.loaded.append(str(p));pins=json.loads(test.fs.nodes[test.flat+'/SOURCE-LOCK.json'].data)['codeAuthority']['ops']
  test.assertTrue(all(any(x[0]==test.flat+'/'+n for x in test.fs.opens) for n in pins))
  return test.registry
 original.NativeTests.setUp=setup;original.NativeTests.load=load
 data=author.inp.data;old_policy_module=data.policy_module
 def policy_module():
  module=old_policy_module();module.__file__='/flat/policy_fence.py'
  actual=module.actual_context;input_tree=module.protected_input_tree
  def context(bundle,selector):
   # The old assertion fixture routes protected_input_tree only for build DATA.
   # Route original67 DATA through the REAL new reader, not that build-only mock.
   outer=module.protected_input_tree
   def route(path):return input_tree(path) if str(path).endswith('/ops') else outer(path)
   with patch.object(module,'protected_input_tree',route):return actual(bundle,selector)
  module.actual_context=context
  return module
 data.policy_module=policy_module
