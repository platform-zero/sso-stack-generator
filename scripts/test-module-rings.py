#!/usr/bin/env python3
"""Source planning tests only: no runtime/admission/installed acceptance."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('module_rings',Path(__file__).with_name('plan-module-rings.py'))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class Planning(unittest.TestCase):
 def fixture(self):
  names=['edge','identity','database','application','executor','build-plugin']
  pins={name:format(i+1,'040x') for i,name in enumerate(names)}
  manifest={'schemaVersion':2,'modules':names,'components':['legacy-broad-core'],'secretStore':'./encrypted.json'}
  lock={'schemaVersion':2,'modules':[{'id':n,'commit':p,'dependencies':['build-plugin'] if n=='identity' else []} for n,p in pins.items()]}
  ir={'modules':[{'id':n,'commit':p} for n,p in pins.items()], 'services':{n:{'module':n,'dependencies':{'database':'healthy'} if n=='identity' else {}} for n in names if n!='build-plugin'}}
  policy={'schemaVersion':1,'rings':[{'name':'foundation','modules':['edge','identity'],'mustExclude':['application']},{'name':'apps','modules':['database','application','build-plugin']},{'name':'execution','modules':['executor']}]}
  return manifest,lock,ir,policy
 def test_module_and_actual_service_edges_close_cumulatively(self):
  args=self.fixture();before=copy.deepcopy(args);p=r.plan(*args)
  self.assertEqual(args,before);self.assertFalse(p['activationAuthority'])
  self.assertEqual(p['rings'][0]['modules'],['build-plugin','database','edge','identity'])
  self.assertEqual(p['rings'][0]['dependencyPromotions'],['build-plugin','database'])
  self.assertEqual(set(p['rings'][-1]['services']),set(args[2]['services']))
  self.assertEqual(p['fullServiceCount'],5);self.assertEqual(len(p['fullModulePins']),6)
  self.assertNotIn('components',p['rings'][0]['manifest'])
  self.assertEqual(p['rings'][0]['manifest']['secretStore'],'./encrypted.json')
 def test_unselected_optional_runner_tool_not_referenced_by_foundation(self):
  args=self.fixture();args[0]['nativeAcceptanceImagePinsPath']='global.settings/native-retained-acceptance-image.json'
  self.assertNotIn('nativeAcceptanceImagePinsPath',r.plan(*args)['rings'][0]['manifest'])
  self.assertIn('nativeAcceptanceImagePinsPath',args[0])
 def test_transitive_service_dependency(self):
  args=self.fixture();args[2]['services']['edge']['dependencies']={'identity':'completed'}
  self.assertIn('database',r.plan(*args)['rings'][0]['modules'])
 def test_cycle_reaches_finite_closure_without_losing_services(self):
  args=self.fixture();args[1]['modules'][2]['dependencies']=['identity']
  self.assertEqual(len(r.plan(*args)['rings']),3)
 def test_missing_or_duplicate_policy_assignment_refuses(self):
  for duplicate in (False,True):
   args=self.fixture()
   if duplicate:args[3]['rings'][1]['modules'].append('edge')
   else:args[3]['rings'][2]['modules'].remove('executor');args[3]['rings'].pop()
   with self.subTest(duplicate=duplicate),self.assertRaises(ValueError):r.plan(*args)
 def test_unknown_policy_module_refuses(self):
  args=self.fixture();args[3]['rings'][0]['modules'].append('foreign')
  with self.assertRaises(ValueError):r.plan(*args)
 def test_pin_drift_or_missing_module_refuses(self):
  for missing in (False,True):
   args=self.fixture()
   if missing:args[2]['modules'].pop()
   else:args[2]['modules'][0]['commit']='f'*40
   with self.subTest(missing=missing),self.assertRaises(ValueError):r.plan(*args)
 def test_actual_dependency_cannot_be_missing_or_condition_weakened(self):
  for name,condition in (('foreign','healthy'),('database','optional')):
   args=self.fixture();args[2]['services']['identity']['dependencies']={name:condition}
   with self.subTest(condition=condition),self.assertRaises(ValueError):r.plan(*args)
 def test_forbidden_foundation_dependency_refuses_not_silently_omits(self):
  args=self.fixture();args[2]['services']['edge']['dependencies']={'application':'healthy'}
  with self.assertRaises(ValueError):r.plan(*args)
 def test_excluded_delivery_module_cannot_reenter(self):
  for field in ('excludedModules','excludedComponents'):
   args=self.fixture();args[0][field]=['application']
   with self.subTest(field=field),self.assertRaises(ValueError):r.plan(*args)
 def test_zero_service_plugin_is_still_required(self):
  args=self.fixture();args[3]['rings'][1]['modules'].remove('build-plugin')
  with self.assertRaises(ValueError):r.plan(*args)
 def test_duplicate_json_key_refuses(self):
  with tempfile.TemporaryDirectory() as temp:
   p=Path(temp)/'public.json';p.write_text('{"modules":[],"modules":["foreign"]}')
   with self.assertRaises(ValueError):r.read_json(p)

if __name__=='__main__':unittest.main()
