"""New C44 controls: exact full saved bindings and real new C42 validator IO.
No actual Root/private target operations; own USER files, internal metadata only.
"""
import contextlib,copy,hashlib,json,os,resource,shutil,stat,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).resolve().parent;S=R
sys.path[:0]=[str(S),str(R),str(R),str(R)]
import run_late_budget as author
import fixture_bridge
fixture_bridge.apply(author)
m=author.inp.core.m;base=author.inp.core.original.NativeTests

class Saved(base):
 def refuse_change(self,change):
  self.crash_phase('intended');state=self.data();before=copy.deepcopy(state[m.KEY]);change(state[m.KEY])
  self.assertNotEqual(m.canonical(state[m.KEY]),m.canonical(before));self.fs.nodes[self.ledger].data=m.encoded(state)
  folder=R/'failed-records';folder.mkdir(exist_ok=True)
  (folder/(self._testMethodName+'.json')).write_bytes(m.encoded(state))
  with self.assertRaises(m.Refused):self.run_api()
  self.assertEqual(self.events('unlink'),[]);self.assertEqual(self.events('rmdir'),[]);self.assertEqual(self.fs.fds,{})
 def test_parent_float_uid(self):self.refuse_change(lambda r:r['parent'].update(uid=0.0))
 def test_parent_float_gid(self):self.refuse_change(lambda r:r['parent'].update(gid=0.0))
 def test_parent_float_dev(self):self.refuse_change(lambda r:r['parent'].update(dev=float(r['parent']['dev'])))
 def test_parent_float_ino(self):self.refuse_change(lambda r:r['parent'].update(ino=float(r['parent']['ino'])))
 def test_parent_float_mode(self):self.refuse_change(lambda r:r['parent'].update(mode=float(r['parent']['mode'])))
 def test_parent_missing_key(self):self.refuse_change(lambda r:r['parent'].pop('uid'))
 def test_parent_extra_key(self):self.refuse_change(lambda r:r['parent'].update(authenticated=True))
 def test_parent_list_not_dict(self):self.refuse_change(lambda r:r.update(parent=list(r['parent'].items())))
 def test_directory_bool_rejected(self):self.refuse_change(lambda r:r['directory'].update(uid=False))
 def test_lease_float_rejected(self):self.refuse_change(lambda r:r['lease'].update(size=0.0))
 def test_original_ledger_bool_rejected(self):self.refuse_change(lambda r:r.update(ledgerSha256Before=False))
 def test_phase_bool_rejected(self):self.refuse_change(lambda r:r.update(phase=False))
 def test_full_binding_positive_reordered_parent(self):
  self.crash_phase('intended');state=self.data();state[m.KEY]['parent']=dict(reversed(list(state[m.KEY]['parent'].items())))
  self.fs.nodes[self.ledger].data=m.encoded(state);result=self.run_api()
  self.assertEqual(result['status'],'retired-inert-control-lease');self.assertEqual(len(self.events('unlink')),1)
  self.assertEqual(len(self.events('rmdir')),1);self.assertEqual(self.fs.fds,{})

class Algorithm(unittest.TestCase):
 def test_nested_literal_positive(self):
  value={'rows':[{'zero':0,'one':1,'flag':False,'float':1.0,'null':None}]}
  self.assertTrue(m._json_exact(value,copy.deepcopy(value)))
 def test_nested_bool_numeric_float_aliases(self):
  for a,b in ((0,False),(1,True),(1,1.0),(0,0.0),(False,0),(True,1),(0.0,-0.0)):
   with self.subTest(a=repr(a),b=repr(b)):
    self.assertFalse(m._json_exact({'rows':[[{'n':a}]]},{'rows':[[{'n':b}]]}))
 def test_non_json_malformed_containers(self):
  class D(dict):pass
  class L(list):pass
  class I(int):pass
  for a,b in ((D(n=1),{'n':1}),(L([1]),[1]),(I(1),1),((1,),[1]),({1:'x'},{'1':'x'}),({True:'x'},{'true':'x'}),(set(),[]),(float('nan'),float('nan')),(float('inf'),float('inf'))):
   with self.subTest(a=repr(a),b=repr(b)):self.assertFalse(m._json_exact(a,b))
 def test_decode_duplicate_nonfinite_and_nonobject(self):
  for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":1e9999}',b'[]',b'{',b'null'):
   with self.subTest(raw=raw),self.assertRaises(m.Refused):m.decoded(raw)

import policy_fence as p
import test_code_target as code
import test_complete_policy_fence as world
code.R=R
world.HERE=R/'real-interop';(world.HERE/'USER_TMP').mkdir(parents=True,exist_ok=True)

def hashes(root):
 out={}
 for file in root.rglob('*'):
  if file.is_file():
   h=hashlib.sha256()
   with file.open('rb') as f:
    while block:=f.read(65536):h.update(block)
   out[str(file.relative_to(root))]=h.hexdigest()
 return out

class RealNewPolicy(unittest.TestCase):
 def test_actual_new_validator_context_full12077_real_code61_target67(self):
  from test_input_data import make_scale,OwnOS
  limit=resource.getrlimit(resource.RLIMIT_NOFILE)
  with world.World() as w:
   f=code.Fixture(w);(w.bundle/'build/empty').unlink();scale=make_scale(w.bundle/'build')
   result,events=f.context();self.assertIsNotNone(result);closure=result[4]
   configured=f.inputs();flat=hashes(f.root);target=hashes(w.bundle/'ops')
   self.assertEqual((len(flat),len(target),len(closure)),(61,67,10))
   self.assertEqual(configured['flat61Sha256'],m.digest(m.canonical(flat)))
   self.assertEqual(configured['code59Sha256'],m.digest(m.canonical({k:v for k,v in flat.items() if k not in ('SOURCE-LOCK.json','inert_control_lease_native.py')})))
   self.assertEqual(closure['ops'],m.digest(m.encoded(target)))
   build=hashes(w.bundle/'build');self.assertEqual(len(build),12077)
   expected={**closure,'ops':m.digest(m.encoded(target)),'build':m.digest(m.encoded(build)),
    'quadlet':m.digest(m.encoded(hashes(w.bundle/'quadlet'))),'site':m.digest(m.encoded(hashes(w.bundle/'site'))),
    'slot':m.digest(m.encoded(hashes(f.slot)))}
   self.assertEqual(closure,expected)
   proxy=OwnOS(w.bundle/'build')
   with patch.object(m,'_os',proxy),contextlib.ExitStack() as stack:
    files,guards=m._data_tree(m.P(str(w.bundle/'build')),stack)
    guards[0].check()
   self.assertEqual(files,build);self.assertEqual(proxy.fds,{});self.assertLessEqual(proxy.peak,3)
   self.assertEqual(resource.getrlimit(resource.RLIMIT_NOFILE),limit)
   loads=[x[5:] for x in events if x.startswith('load:')]
   self.assertEqual(len(loads),4);self.assertTrue(all(Path(x).parent==f.root for x in loads))
   sizes=[x.stat().st_size for x in (w.bundle/'build').rglob('*') if x.is_file()]
   self.assertEqual((sum(sizes),sizes.count(0),max(sizes)),(165832391,18,25409160))
   (R/'NEW-POLICY-FULL-SCALE.json').write_text(json.dumps({'policySha256':m.digest((S/'policy_fence.py').read_bytes()),'nativeSha256':m.digest((S/'inert_control_lease_native.py').read_bytes()),'scale':scale,'flat61':configured['flat61Sha256'],'code59':configured['code59Sha256'],'target67Ops':closure['ops'],'TEN':closure,'realTrackedFdPeak':proxy.peak,'defaultFdLimitUnchanged':True,'realNewValidatorAndActualContext':True,'scope':'actual own USER full trees; explicit internal privileged/stage/slot facts only; NOT native'},indent=2)+'\n')

