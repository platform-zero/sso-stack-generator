import unittest
from unittest.mock import patch
import inert_control_lease_native as m
class Dispatch(unittest.TestCase):
 def test_admitted_callable_dispatches_native_engine_not_always_refusal(self):
  args=('/public-fake/bundle','/public-fake/selector','/public-fake/ledger','a'*64,'b'*64,'c'*64)
  with patch.object(m,'root_admission',return_value=None),patch.object(m,'_retire',return_value={'status':'retired-inert-control-lease'}) as engine:
   self.assertEqual(m.retire_inert_control_lease(*args),{'status':'retired-inert-control-lease'})
   engine.assert_called_once_with(*args)
if __name__=='__main__':unittest.main()
