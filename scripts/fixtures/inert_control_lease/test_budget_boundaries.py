"""New boundary controls; original eight pre-fix bodies remain byte-identical."""
from unittest.mock import patch
from test_late_budget import Late
class Boundaries(Late):
 def c_exact120_refuses_before_unlink(self):
  advancing=self.clock.advance
  self.clock.advance=lambda seconds,label:advancing(40 if seconds==46 else seconds,label)
  self.scenario='unlink';outcome=self.outcome();self.proof('exact120',outcome)
  self.assertEqual(self.clock.value,120);self.assertEqual(outcome.get('reason'),'operation-timeout')
  self.assertEqual(self.events('unlink'),[]);self.assertEqual(self.fs.fds,{})
 def c_119997_full_flow_still_succeeds(self):
  advancing=self.clock.advance
  self.clock.advance=lambda seconds,label:advancing(39.999 if seconds==46 else seconds,label)
  self.scenario='unlink';outcome=self.outcome();self.proof('119997',outcome)
  self.assertEqual(outcome.get('status'),'retired-inert-control-lease');self.assertLess(self.clock.value,120)
  self.assertEqual(len(self.events('unlink')),1);self.assertEqual(len(self.events('rmdir')),1);self.assertEqual(self.fs.fds,{})
 def c_already_issued_call_not_undone_then_explicit_owned_absence(self):
  deleting=self.fs.unlink;syncing=self.fs.fsync;after=[];issued=[]
  def delayed(*a,**kw):
   result=deleting(*a,**kw);issued.append(True);self.clock.advance(121,'in-flight-unlink-return');return result
  def syncing_after(fd):
   if issued:after.append(self.clock.value)
   return syncing(fd)
  with patch.object(self.fs,'unlink',delayed),patch.object(self.fs,'fsync',syncing_after):first=self.outcome()
  self.assertEqual(first.get('reason'),'operation-timeout');self.assertEqual(after,[])
  self.assertEqual(len(self.events('unlink')),1);self.assertEqual(self.events('rmdir'),[]);self.assertEqual(self.fs.fds,{})
  self.assertEqual(self.data()['venueInertControlLeaseRetirement']['phase'],'lease-delete-issued')
  before=self.clock.value;second=self.outcome() # separate explicit invocation, never helper retry/clock reset
  self.assertEqual(second.get('status'),'retired-inert-control-lease');self.assertEqual(self.clock.value,before)
  self.assertEqual(len(self.events('unlink')),1);self.assertEqual(len(self.events('rmdir')),1);self.assertEqual(self.fs.fds,{})
