import json,sys,types,unittest
from pathlib import Path
import run_input as current
m=current.core.m;fixture=current.core.fixture;original=current.core.original
R=Path(__file__).resolve().parent
class CoherentFacts(original.NativeTests):
 def run_api(self,epoch=None):
  # C32 changes the AUTHENTICATED actual plan by adding integer schemaVersion1.
  # Rebind only synthetic protected config to that exact actual plan/current
  # ledger. Never change/coerce the saved ledger plan or repair its types.
  node=self.fs.nodes[self.flat+'/SOURCE-LOCK.json'];cfg=json.loads(node.data)
  target=cfg['targetAuthority']['inputConfiguration'];target['planSha256']=self.plan_sha
  if m.KEY not in self.data():target['initialReviewedLedgerSha256']=m.digest(self.fs.nodes[self.ledger].data)
  node.data=m.encoded(cfg)
  try:return super().run_api(epoch)
  except m.Refused as e:return {'status':'refused','reason':str(e)}
adapter=types.ModuleType("review");adapter.m=m;adapter.fixture=fixture;adapter.Independent=CoherentFacts;adapter.S=R/"historical_shape"
sys.modules["review"]=adapter
from c32_case import Coherent
