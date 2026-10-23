"""Full SOURCE cohort. Never select/deploy/invoke a real Root operation."""
import importlib.util,json,sys,unittest
from pathlib import Path
R=Path(__file__).resolve().parent;sys.path.insert(0,str(R))
import run_corrected as core
import test_input_data as data

def suite():
 s=unittest.TestSuite();s.addTests(unittest.defaultTestLoader.loadTestsFromModule(core.original));s.addTests(unittest.defaultTestLoader.loadTestsFromModule(core.dispatch));s.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(core.ActualUser))
 for n in sorted(n for n in dir(core.Review) if n.startswith('r_') and n!='r_complete_fc98_closure_should_interoperate'):s.addTest(core.Review(n))
 for n in sorted(n for n in dir(core.Corrected) if n.startswith('c_')):s.addTest(core.Corrected(n))
 for cls in (data.RealData,data.Tmpfiles,data.FullContext):
  for n in sorted(n for n in dir(cls) if n.startswith('d_')):s.addTest(cls(n))
 return s
if __name__=='__main__':
 result=unittest.TextTestRunner(verbosity=2).run(suite())
 out={'testsRun':result.testsRun,'failures':[{'test':str(t),'trace':x} for t,x in result.failures],'errors':[{'test':str(t),'trace':x} for t,x in result.errors],'skipped':result.skipped,'scope':'SOURCE/fakes + actual own USER input-tree FDs ONLY; no installed/native acceptance'}
 (R/'INPUT-RESULTS.json').write_text(json.dumps(out,indent=2)+'\n');sys.exit(bool(result.failures or result.errors))
