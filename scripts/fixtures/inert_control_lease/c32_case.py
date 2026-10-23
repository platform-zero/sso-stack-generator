import copy,json,unittest
from pathlib import Path
import review
m=review.m;fixture=review.fixture
R=Path(__file__).resolve().parent
class Coherent(unittest.TestCase):
 def setup_case(self):
  c=review.Independent('runTest');c.setUp();self.addCleanup(c.doCleanups);return c
 def test_boolean_plan_alias_not_a_literal_policy47_state(self):
  c=self.setup_case();c.plan['schemaVersion']=1;c.plan_sha=m.digest(m.canonical(c.plan))
  state=c.data();state['plan']=copy.deepcopy(c.plan);state['plan']['schemaVersion']=True
  state[m.FENCE]['planSha256']=c.plan_sha;fixture.rechain(state);c.fs.nodes[c.ledger].data=m.encoded(state)
  namespace={'__name__':'own_policy47','__file__':str(review.S/'policy_fence.py')}
  exec(compile((review.S/'policy_fence.py').read_bytes(),'<own-policy47>','exec'),namespace)
  policy_refused=False
  try:namespace['retirement_shape'](state,c.plan,c.context)
  except namespace['Refused']:policy_refused=True
  self.assertTrue(policy_refused,'literal actual47 policy typed plan gate must reject this state')
  outcome=c.run_api()
  evidence={'policy47Refused':policy_refused,'pythonPlanEquality':state['plan']==c.plan,
   'canonicalPlanEquality':m.canonical(state['plan'])==m.canonical(c.plan),'coherentFullFenceKeys':len(state[m.FENCE]),
   'distinctEpochs':len(set(state[m.FENCE]['intendedEpochs'])),'nativeLeaseOutcome':outcome,
   'unlink':c.events('unlink'),'rmdir':c.events('rmdir'),'runtimePresent':c.runtime in c.fs.nodes}
  (R/'evidence/BOOLEAN-PLAN-FULL-FLOW.json').write_text(json.dumps(evidence,indent=2)+'\n')
  self.assertEqual(c.events('unlink'),[],'malformed typed plan was accepted despite literal policy47 refusal')
