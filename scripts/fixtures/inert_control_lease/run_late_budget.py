import json,sys,unittest
from pathlib import Path
R=Path(__file__).resolve().parent;sys.path.insert(0,str(R))
import test_late_budget as late
import test_budget_boundaries as boundary
import run_input as inp
import typed_plan_probe as c32
import test_typed_plan as typed

def suite(full):
 s=unittest.TestSuite()
 if full:
  s.addTests(inp.suite());s.addTest(c32.Coherent('test_boolean_plan_alias_not_a_literal_policy47_state'))
  for n in sorted(n for n in dir(typed.Typed) if n.startswith('p_')):s.addTest(typed.Typed(n))
 for n in sorted(n for n in dir(late.Late) if n.startswith('b_')):s.addTest(late.Late(n))
 if full:
  for n in sorted(n for n in dir(boundary.Boundaries) if n.startswith('c_')):s.addTest(boundary.Boundaries(n))
 return s
if __name__=='__main__':
 mode=sys.argv[1];result=unittest.TextTestRunner(verbosity=2).run(suite(mode!='baseline'))
 summary={'mode':mode,'testsRun':result.testsRun,'failures':[{'test':str(t),'trace':v} for t,v in result.failures],
  'errors':[{'test':str(t),'trace':v} for t,v in result.errors],'skipped':result.skipped,'scope':'SOURCE/fake clock/context/backend; actual modeled effects, NOT native exploit or Root authority'}
 (R/(mode.upper()+'-RESULTS.json')).write_text(json.dumps(summary,indent=2)+'\n');sys.exit(bool(result.failures or result.errors))
