"""Synthetic private configuration ONLY; complete PUBLIC committed source bodies.
Real own USER files/FDs; explicit internal Root/slot/module fakes are NOT authority.
"""
from contextlib import ExitStack
import copy,json,os,shutil,stat,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import policy_fence as p
import test_complete_policy_fence as a
R=Path(__file__).resolve().parent
REAL_INPUTS=p._policy_inputs;REAL_CONTEXT=p.actual_context;REAL_FILE=p.protected_file;REAL_CODE=p.closed_code_tree;REAL_SLOT=p._slot_members

class Fixture:
 def __init__(self,w):
  self.w=w;self.root=w.root/'CODE';self.root.mkdir(mode=0o700)
  self.profile=json.loads((R/'SOURCE-LOCK.template.json').read_text())
  for source in (R/'generator/code57').iterdir():shutil.copyfile(source,self.root/source.name)
  self.body=Path(p.__file__).read_bytes();(self.root/'policy_fence.py').write_bytes(self.body)
  native=R
  shutil.copyfile(native/'inert_control_lease_native.py',self.root/'inert_control_lease_native.py')
  ec4=R/'generator/retire-failed-venue-registry-image.py'
  shutil.copyfile(ec4,self.root/ec4.name)
  target=w.bundle/'ops';target.mkdir(mode=0o700);records={}
  for source in (R/'generator/target57').iterdir():shutil.copyfile(source,target/source.name)
  for name in p.GENERATED_OPS:(target/name).write_bytes(('PUBLIC SYNTHETIC GENERATED '+name+'\n').encode())
  for source in target.iterdir():source.chmod(0o600);records[source.name]={'sha256':p.sha(source.read_bytes()),'mode':0o600}
  w.plan['sourceCommit']=p.TARGET_COMMIT;state=w.read();state['plan']=copy.deepcopy(w.plan);w.save(state)
  w.provenance=p.encode({'generatorCommit':p.TARGET_COMMIT,'generatorDirty':False,'siteDirty':False})
  (w.bundle/'source-provenance.json').write_bytes(w.provenance)
  for name in ('podman-domains.json','stack.ir.json','site/agent-vm.json','site/global.settings/registry-image-ids.json'):
   path=w.bundle/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);path.write_bytes(b'{}')
  (w.bundle/'quadlet').mkdir(mode=0o700);(w.bundle/'build').mkdir(mode=0o700);(w.bundle/'build/empty').touch()
  receipt=w.root/'synthetic-historical-receipt';receipt.write_bytes(b'PUBLIC opaque historical bytes NOT invented output JSON');receipt.chmod(0o600)
  cfg={'schemaVersion':1,'bundlePath':str(w.bundle),'selectorPath':str(w.selector),'ledgerPath':str(w.ledger),
       'provenanceSha256':p.sha(w.provenance),'planSha256':p.sha(p.canonical(w.plan)),
       'initialReviewedLedgerSha256':p.sha(w.ledger.read_bytes()),'historicalArtifactReceiptPath':str(receipt),
       'historicalArtifactReceiptSha256':p.sha(receipt.read_bytes()),'ops':records}
  self.profile['targetAuthority']['inputConfiguration']=cfg;self.profile['targetAuthority']['namespace']=w.ns
  self.profile['policyFenceSha256']=p.sha(self.body)
  self.profile['nativeLeaseSha256']=p.sha((self.root/'inert_control_lease_native.py').read_bytes())
  self.save()
  for source in self.root.iterdir():source.chmod(0o600)
  self.slot=w.root/'slot';self.slot.mkdir(mode=0o700)
  controller=(native/'public-controller/ops/p0_host_context.py').read_bytes();(self.slot/'p0_host_context.py').write_bytes(controller)
  self.manifest={'files':{'p0_host_context.py':p.sha(controller)}};(self.slot/'manifest.json').write_bytes(p.encode(self.manifest))
  w.context.data={'controlCommit':p.CONTROLLER['commit'],'sourceProvenanceSha256':p.sha(w.provenance),'siteVmSpecSha256':p.sha(b'{}')}
  units=self.slot/'units';units.mkdir(mode=0o700)
  state=w.read()
  for original in p.HOST_UNITS:
   body=('PUBLIC SLOT UNIT '+original).encode();(units/original).write_bytes(body)
   self.manifest['files']['units/'+original]=p.sha(body)
   for row in state['venueHostUnitsRetirement']['units']:
    if row['path'].endswith(w.context.unit(original)):row['sha256']=p.sha(body)
  (self.slot/'manifest.json').write_bytes(p.encode(self.manifest))
  w.closure['provenanceSha256']=p.sha(w.provenance);w.closure['frozenRegistrySha256']=p.sha(b'{}')
  state['venueRegistryFrozenSha256']=p.sha(b'{}');state['venueRegistryFailedPendingRetirement']['sourceProvenanceSha256']=p.sha(w.provenance)
  w.save(state);cfg['initialReviewedLedgerSha256']=p.sha(w.ledger.read_bytes());self.save()
 def save(self):(self.root/'SOURCE-LOCK.json').write_bytes(p.encode(self.profile));(self.root/'SOURCE-LOCK.json').chmod(0o600)
 def inputs(self):
  with patch.object(p,'__file__',str(self.root/'policy_fence.py')):return REAL_INPUTS(self.w.bundle,self.w.selector)
 def context(self,drift=False,badslot=False,full=False):
  w=self.w;pointer=w.source/'agent-services-current-host';slot=w.source/'agent-service-releases/host-fake';events=[];resolved=[]
  class KernelPath(type(Path())):
   def lstat(self):
    if str(self)==str(pointer):return SimpleNamespace(st_uid=0,st_mode=stat.S_IFLNK|0o777)
    return super().lstat()
   def resolve(self,strict=False):
    if str(self)==str(pointer):
     resolved.append(True);return KernelPath(str(slot)+('-changed' if drift and len(resolved)>1 else ''))
    return super().resolve(strict=strict)
  def mapped(path):
   if type(path) is int:return path # native lease lists an OWN already-held directory FD
   path=Path(path)
   return self.slot/path.relative_to(slot) if path.is_relative_to(slot) else path
  listing=os.listdir
  def read(path,maximum):return REAL_FILE(mapped(path),maximum)
  def code(path):
   events.append('close:'+str(path))
   if badslot and str(path)==str(slot):raise p.Refused('own-slot-cache')
   return REAL_CODE(mapped(path))
  def load(path,name):
   events.append('load:'+str(path))
   if Path(path).name=='venue-owned-stage.py':return SimpleNamespace(owned_plan=lambda *args:w.plan,safe_parents=lambda *args:w.created)
   if Path(path).name=='venue-start-quarantine.py':return SimpleNamespace(host_context=lambda *args:w.context)
   if Path(path).name=='venue-unit-stage.py':return SimpleNamespace(manifest=lambda *args:w.units)
   if Path(path).name=='venue-image-authority.py':return SimpleNamespace(authority=lambda *args:w.closure)
   raise AssertionError('foreign source loader')
  with patch.object(p,'__file__',str(self.root/'policy_fence.py')),patch.object(p,'Path',KernelPath),patch.object(p,'protected_file',read),patch.object(p,'closed_code_tree',code),patch.object(p.os,'listdir',side_effect=lambda path:listing(mapped(path))),patch.object(p,'_slot_members',side_effect=lambda path:REAL_SLOT(mapped(path))),patch.object(p,'load_closed',load):
   try:
    if full:
     from test_tmpfiles_quiescence import boot,text
     query=w.sysd
     def observed(args):
      if args[0]=='show' and args[1] in p.TMPFILES:return 0,text(boot(args[1]))
      return query(args)
     with patch.object(p,'actual_context',side_effect=REAL_CONTEXT),patch.object(p,'_systemctl',side_effect=observed):result=w.run()
    else:result=REAL_CONTEXT(KernelPath(str(w.bundle)),KernelPath(str(w.selector)))
   except p.Refused:return None,events
  return result,events

class CodeTargetTests(unittest.TestCase):
 def test_complete_57_code_67_data_and_59_61_c39_hashes(self):
  with a.World() as w:
   f=Fixture(w);result=f.inputs();flat={x.name:p.sha(x.read_bytes()) for x in f.root.iterdir()}
   self.assertEqual(len(flat),61);self.assertEqual(len(f.profile['targetAuthority']['inputConfiguration']['ops']),67)
   self.assertEqual(result['flat61Sha256'],p.sha(p.canonical(flat)))
   self.assertEqual(result['code59Sha256'],p.sha(p.canonical({n:h for n,h in flat.items() if n not in ('SOURCE-LOCK.json','inert_control_lease_native.py')})))
   self.assertEqual(result['opsSha256'],p.sha(p.encode({n:r['sha256'] for n,r in f.profile['targetAuthority']['inputConfiguration']['ops'].items()})))
 def test_original_target_modules_never_loaded_and_ten_ops_is_original_data(self):
  with a.World() as w:
   f=Fixture(w);result,events=f.context();self.assertIsNotNone(result)
   loads=[x[5:] for x in events if x.startswith('load:')]
   self.assertEqual(len(loads),4);self.assertTrue(all(Path(x).parent==f.root for x in loads))
   self.assertFalse(any(str(w.bundle/'ops') in x for x in loads))
   self.assertEqual(len(result[4]),10);self.assertEqual(result[4]['ops'],f.inputs()['opsSha256'])
 def test_b7_wrong_code_foreign_extra_cache_and_missing_config_refuse(self):
  for kind in ('b7','extra','cache','missing','null'):
   with self.subTest(kind=kind),a.World() as w:
    f=Fixture(w)
    if kind=='b7':
     # owned-stage bytes happen to be IDENTICAL across the public epochs.
     # Challenge a genuinely changed dependency, without weakening refusal.
     self.assertNotEqual((R/'generator/target57/venue-start-quarantine.py').read_bytes(),(R/'generator/code57/venue-start-quarantine.py').read_bytes())
     shutil.copyfile(R/'generator/target57/venue-start-quarantine.py',f.root/'venue-start-quarantine.py')
    if kind in ('extra','cache'):(f.root/('foreign.py' if kind=='extra' else 'foreign.pyc')).write_bytes(b'never execute')
    if kind=='missing':(f.root/'SOURCE-LOCK.json').unlink()
    if kind=='null':f.profile['targetAuthority']['inputConfiguration']=None;f.save()
    with self.assertRaises((p.Refused,FileNotFoundError)):f.inputs()
 def test_typed_configuration_paths_provenance_and_receipt_controls(self):
  for kind in ('bool','path','prov','receipt','mode'):
   with self.subTest(kind=kind),a.World() as w:
    f=Fixture(w);cfg=f.profile['targetAuthority']['inputConfiguration']
    if kind=='bool':cfg['schemaVersion']=True
    if kind=='path':cfg['bundlePath']=str(w.bundle/'..')
    if kind=='prov':cfg['provenanceSha256']='0'*64
    if kind=='receipt':Path(cfg['historicalArtifactReceiptPath']).write_bytes(b'changed own bytes')
    if kind=='mode':Path(cfg['historicalArtifactReceiptPath']).chmod(0o644)
    f.save()
    with self.assertRaises(p.Refused):f.inputs()
 def test_target67_foreign_missing_body_mode_and_generated_names_refuse(self):
  for kind in ('extra','missing','body','mode','names'):
   with self.subTest(kind=kind),a.World() as w:
    f=Fixture(w);root=w.bundle/'ops';name=next(iter(p.GENERATED_OPS))
    if kind=='extra':(root/'foreign').write_bytes(b'foreign')
    if kind=='missing':(root/name).unlink()
    if kind=='body':(root/name).write_bytes(b'changed')
    if kind=='mode':(root/name).chmod(0o644)
    if kind=='names':f.profile['targetAuthority']['generatedNames'][0]='foreign';f.save()
    with self.assertRaises(p.Refused):f.inputs()
 def test_slot_cache_closed_before_lifecycle_and_current_change_refuses(self):
  for kind in ('cache','current'):
   with self.subTest(kind=kind),a.World() as w:
    f=Fixture(w);result,events=f.context(drift=kind=='current',badslot=kind=='cache');self.assertIsNone(result)
    if kind=='cache':self.assertFalse(any('load:' in x and x.endswith('venue-start-quarantine.py') for x in events))
 def test_real_new_config_and_context_full_fence_positive(self):
  with a.World() as w:
   f=Fixture(w);result,events=f.context(full=True);self.assertIsNotNone(result)
   self.assertEqual(result['policiesAbsent'],2);record=w.read()[p.KEY]
   self.assertEqual(len(record),14);self.assertEqual(len(record['intendedEpochs']),6)
   self.assertEqual(w.unlinks,[r[0].name for r in w.specs])
   self.assertTrue(all(Path(x[5:]).parent==f.root for x in events if x.startswith('load:')))

 def test_public_template_is_null_and_api_14field_deadline_sources_unchanged(self):
  template=json.loads((R/'SOURCE-LOCK.template.json').read_text());self.assertIsNone(template['targetAuthority']['inputConfiguration'])
  import inspect
  self.assertEqual(list(inspect.signature(p.fence_host_transport_policies).parameters),['bundle','selector','ledger','reviewed_sha','provenance_sha'])
  self.assertIn('epoch=reviewed_sha;deadline=time.monotonic()+90',inspect.getsource(p._fence))
 def test_private_pre_fence_ledger_binding_is_not_post_fence_configuration(self):
  with a.World() as w:
   f=Fixture(w);cfg=f.profile['targetAuthority']['inputConfiguration'];cfg['initialReviewedLedgerSha256']='0'*64;f.save()
   with patch.object(p,'__file__',str(f.root/'policy_fence.py')),self.assertRaises(p.Refused):w.run()
   self.assertEqual(w.unlinks,[]);self.assertNotIn(p.KEY,w.read())
