#!/usr/bin/env python3
"""SOURCE/fake gate: deletion-only abandonment never becomes a pull retry."""
import contextlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
p=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-registry-images.py'
s=importlib.util.spec_from_file_location('abandoned_registry_source',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class AbandonedPreparation(unittest.TestCase):
 def test_any_abandonment_field_refuses_before_inventory_or_fetch(self):
  for value in (True,False,None,0,1,'retired',{},[]):
   with self.subTest(value=value),patch.object(m,'journal',return_value=(None,{'venueRegistryPreparationAbandoned':value},{},{})),patch.object(m,'fetch')as fetch,patch.object(m,'probe')as probe,patch.object(m,'command_graphs')as graphs:
    with self.assertRaisesRegex(m.Refusal,'abandoned'):m.prepare('FAKE-bundle','FAKE-selector','FAKE-site','FAKE-ledger',1)
    fetch.assert_not_called();probe.assert_not_called();graphs.assert_not_called()
 def test_absence_keeps_existing_bounded_input_refusal(self):
  with patch.object(m,'journal',return_value=(None,{},{},{})):
   with self.assertRaisesRegex(m.Refusal,'one to sixty'):m.prepare('FAKE-bundle','FAKE-selector','FAKE-site','FAKE-ledger',0)
class SharedPreparationLease(unittest.TestCase):
 def test_locked_worker_only_runs_inside_same_lifecycle_lease(self):
  active=False
  @contextlib.contextmanager
  def lease(*args):
   nonlocal active
   active=True
   try:yield
   finally:active=False
  def locked(*args):self.assertTrue(active);return 'SOURCE-only-result'
  with patch.object(m,'journal',return_value=(None,{},{},{})),patch.object(m,'preparation_lease',lease),patch.object(m,'prepare_locked',locked):self.assertEqual(m.prepare('FAKE','FAKE','FAKE','FAKE',1),'SOURCE-only-result')
  self.assertFalse(active)
 def test_lease_refusal_never_reaches_mutation_worker(self):
  with patch.object(m,'journal',return_value=(None,{},{},{})),patch.object(m,'preparation_lease',side_effect=m.Refusal('SOURCE fake contention')),patch.object(m,'prepare_locked')as locked:
   with self.assertRaises(m.Refusal):m.prepare('FAKE','FAKE','FAKE','FAKE',1)
   locked.assert_not_called()
 def test_abandonment_appears_under_lease_is_rechecked(self):
  with patch.object(m,'journal',side_effect=[(None,{},{},{}),(None,{'venueRegistryPreparationAbandoned':True},{},{})]),patch.object(m,'preparation_lease',return_value=contextlib.nullcontext()),patch.object(m,'fetch')as fetch:
   with self.assertRaisesRegex(m.Refusal,'abandoned'):m.prepare('FAKE','FAKE','FAKE','FAKE',1)
   fetch.assert_not_called()
if __name__=='__main__':unittest.main()
