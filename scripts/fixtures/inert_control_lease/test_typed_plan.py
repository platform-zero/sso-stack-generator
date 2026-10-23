"""Coherent full-engine type controls. Explicit internal fakes; never native.
All complete14-field/six-epoch/S1-configuration bindings are rebuilt over the
actual SAVED bytes, including malformed types; no coercion or early stale gate.
"""
import copy,json,unittest
from unittest.mock import patch
import run_input as current
m=current.core.m;fixture=current.core.fixture;original=current.core.original
class Typed(original.NativeTests):
 def setUp(self):
  super().setUp()
  self.plan['schemaVersion']=1
  self.plan['typedControls']={'flag':True,'zero':0,'ratio':1.0,'signedZero':0.0,
   'nested':[{'count':1,'enabled':False,'values':[0,1.0]}]}
  self.plan_sha=m.digest(m.canonical(self.plan));self.coherent(copy.deepcopy(self.plan))
 def coherent(self,saved):
  state=self.data();state['plan']=copy.deepcopy(saved);state[m.FENCE]['planSha256']=self.plan_sha
  fixture.rechain(state);raw=m.encoded(state);self.fs.nodes[self.ledger].data=raw
  node=self.fs.nodes[self.flat+'/SOURCE-LOCK.json'];cfg=json.loads(node.data)
  cfg['targetAuthority']['inputConfiguration']['planSha256']=self.plan_sha
  cfg['targetAuthority']['inputConfiguration']['initialReviewedLedgerSha256']=m.digest(raw);node.data=m.encoded(cfg)
  self.assertEqual(len(state[m.FENCE]),14);self.assertEqual(len(set(state[m.FENCE]['intendedEpochs'])),6)
  self.assertEqual(state[m.FENCE]['planSha256'],m.digest(m.canonical(self.plan)))
  return raw
 def refuse_alias(self,change):
  saved=copy.deepcopy(self.plan);change(saved);raw=self.coherent(saved)
  self.assertEqual(saved,self.plan,'counterexample must retain Python equality')
  self.assertNotEqual(m.canonical(saved),m.canonical(self.plan))
  original_bytes={n:self.fs.nodes[n].data for n in (self.ledger,self.runtime+'/lifecycle.lock')}
  with patch.object(m,'_json_exact',wraps=m._json_exact) as gate:
   with self.assertRaises(m.Refused):self.run_api()
  self.assertTrue(gate.called,'must reach the intended full-plan type gate')
  self.assertEqual(self.events('unlink'),[]);self.assertEqual(self.events('rmdir'),[]);self.assertEqual(self.events('replace'),[])
  self.assertEqual(self.fs.nodes[self.ledger].data,raw)
  self.assertEqual({n:self.fs.nodes[n].data for n in original_bytes},original_bytes)
 def p_integer_full_flow_positive(self):
  before=copy.deepcopy(self.data()[m.FENCE]);self.run_api()
  self.assertEqual(len(self.events('unlink')),1);self.assertEqual(len(self.events('rmdir')),1)
  self.assertEqual(self.data()[m.FENCE],before);self.assertIs(type(self.data()['plan']['schemaVersion']),int)
 def p_reordered_objects_positive(self):
  self.coherent(dict(reversed(list(self.plan.items()))));self.run_api()
  self.assertEqual(len(self.events('unlink')),1);self.assertEqual(len(self.events('rmdir')),1)
 def p_bool_schema(self):self.refuse_alias(lambda p:p.update(schemaVersion=True))
 def p_float_schema(self):self.refuse_alias(lambda p:p.update(schemaVersion=1.0))
 def p_bool_zero(self):self.refuse_alias(lambda p:p['typedControls'].update(zero=False))
 def p_float_zero(self):self.refuse_alias(lambda p:p['typedControls'].update(zero=0.0))
 def p_bool_flag_as_int(self):self.refuse_alias(lambda p:p['typedControls'].update(flag=1))
 def p_float_flag_as_float(self):self.refuse_alias(lambda p:p['typedControls'].update(flag=1.0))
 def p_nested_bool_count(self):self.refuse_alias(lambda p:p['typedControls']['nested'][0].update(count=True))
 def p_nested_float_count(self):self.refuse_alias(lambda p:p['typedControls']['nested'][0].update(count=1.0))
 def p_nested_false_as_zero(self):self.refuse_alias(lambda p:p['typedControls']['nested'][0].update(enabled=0))
 def p_nested_list_zero_as_float(self):self.refuse_alias(lambda p:p['typedControls']['nested'][0]['values'].__setitem__(0,0.0))
 def p_nested_list_float_as_int(self):self.refuse_alias(lambda p:p['typedControls']['nested'][0]['values'].__setitem__(1,1))
 def p_same_float_type_negative_zero(self):self.refuse_alias(lambda p:p['typedControls'].update(signedZero=-0.0))
 def p_non_string_keys_never_json_coerced(self):
  self.assertFalse(m._json_exact({1:'public'},{'1':'public'}));self.assertFalse(m._json_exact({True:'public'},{'true':'public'}))
 def p_non_json_container_never_json_coerced(self):
  self.assertFalse(m._json_exact({'nested':(1,2)},{'nested':[1,2]}))
