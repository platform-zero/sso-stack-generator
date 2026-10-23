"""Additional exact saved-parent type and absence-continuation probes."""
import copy,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).resolve().parent
sys.path.insert(0,str(R))
from independent import Independent,m
class Supplemental(Independent):
 def parent_alias(self,key,value):
  self.crash_phase('intended')
  state=self.data();before=copy.deepcopy(state[m.KEY]);state[m.KEY]['parent'][key]=value
  self.assertEqual(state[m.KEY],before)
  self.assertNotEqual(m.canonical(state[m.KEY]),m.canonical(before))
  self.fs.nodes[self.ledger].data=m.encoded(state)
  result=self.outcome()
  (R/('PARENT-'+key+'.json')).write_text(json.dumps({'key':key,'aliased':value,'original':before['parent'][key],'result':result,'unlink':self.events('unlink'),'rmdir':self.events('rmdir'),'openFDs':len(self.fs.fds),'scope':'coherent saved continuation metadata; SOURCE only, not native Root exploit'},indent=2)+'\n')
  self.assertEqual(self.fs.fds,{})
  self.assertEqual(result['status'],'refused','noncanonical typed parent binding must refuse')
  self.assertEqual(self.events('unlink'),[])
 def test_parent_uid_bool_alias(self):self.parent_alias('uid',False)
 def test_parent_gid_bool_alias(self):self.parent_alias('gid',False)
 def test_parent_dev_bool_alias(self):self.parent_alias('dev',True)
 def test_owned_absence_continuation_fsync_exact120(self):
  old=self.fs.unlink
  def issued(*a,**kw):
   old(*a,**kw);raise OSError('SYNTHETIC interrupted immediately after unlink')
  with patch.object(self.fs,'unlink',issued):first=self.outcome()
  self.assertEqual(first['status'],'refused');self.assertEqual(len(self.events('unlink')),1)
  self.assertEqual(self.data()[m.KEY]['phase'],'lease-delete-issued')
  original=m._Native.runtime_now
  def delay(native,*a,**kw):
   result=original(native,*a,**kw)
   if not self.fired and native.record['phase']=='lease-delete-issued' and not self.inside('check') and not self.inside('open_runtime'):
    self.fired.append(True);self.now=120.
   return result
  with patch.object(m._Native,'runtime_now',delay):second=self.outcome()
  self.assertEqual(self.fired,[True]);self.assertEqual(second.get('reason'),'operation-timeout')
  self.assertEqual(len(self.events('unlink')),1);self.assertEqual(self.events('rmdir'),[])
  self.assertEqual([e for e in self.effects if e[1]>=120],[]);self.assertEqual(self.fs.fds,{})

if __name__=='__main__':
 result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Supplemental(n) for n in sorted(n for n in Supplemental.__dict__ if n.startswith('test_'))))
 (R/'SUPPLEMENTAL-RESULTS.json').write_text(json.dumps({'tests':result.testsRun,'failures':[{'test':str(t),'trace':v} for t,v in result.failures],'errors':[{'test':str(t),'trace':v} for t,v in result.errors],'skipped':result.skipped},indent=2)+'\n')
 sys.exit(bool(result.failures or result.errors))
