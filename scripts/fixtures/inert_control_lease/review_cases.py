"""Independent C47 SOURCE adversarial cases. All privilege/context observations
are INTERNAL fakes; file/FD/journal/unlink effects only in own USER trees.
"""
import copy,inspect,json,os,stat,unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
import policy_fence as p
import test_complete_policy_fence as a
import test_code_target as c
from test_tmpfiles_quiescence import boot,text
from c30_fd_tests import Monitor

@contextmanager
def legacy_case():
 with a.World() as w:
  w.plan['sourceCommit']=p.TARGET_COMMIT;s=w.read();s['plan']=copy.deepcopy(w.plan);w.save(s)
  w.context.data={'controlCommit':p.CONTROLLER['commit'],'sourceProvenanceSha256':p.sha(w.provenance),'siteVmSpecSha256':p.sha(b'{}')}
  def inputs(bundle,selector):
   state=w.read();prior=state.get(p.KEY)
   cfg={'ledgerPath':str(w.ledger),'initialReviewedLedgerSha256':prior['ledgerSha256Before'] if type(prior) is dict else p.sha(w.ledger.read_bytes()),'planSha256':p.sha(p.canonical(w.plan)),'provenanceSha256':p.sha(w.provenance)}
   return {'root':str(c.R),'opsSha256':w.closure['ops'],'pins':{'targetAuthority':{'inputConfiguration':cfg,'namespace':w.ns}}}
  query=w.sysd
  def systemctl(args):
   if args[0]=='show' and args[1] in p.TMPFILES:return 0,text(boot(args[1]))
   return query(args)
  with patch.object(p,'_policy_inputs',side_effect=inputs),patch.object(p,'_systemctl',side_effect=systemctl):yield w

def stop_intended(w):
 original=p.Journal.write;fired=[]
 def written(journal,*args):
  result=original(journal,*args)
  if w.read().get(p.KEY,{}).get('phase')=='intended':fired.append(True);raise p.Refused('own-stop-after-intended')
  return result
 with patch.object(p.Journal,'write',written):
  try:w.run()
  except p.Refused:pass
 assert fired==[True] and w.read()[p.KEY]['phase']=='intended' and not w.unlinks

def numeric_paths(value,prefix=()):
 if type(value) is dict:
  for key,item in value.items():yield from numeric_paths(item,prefix+(key,))
 elif type(value) is list:
  for key,item in enumerate(value):yield from numeric_paths(item,prefix+(key,))
 elif type(value) is int:yield prefix,value

def put(root,path,value):
 for key in path[:-1]:root=root[key]
 root[path[-1]]=value

class SavedRecord(unittest.TestCase):
 def strict(self,w,state):
  w.save(state);before=w.ledger.read_bytes();unlinks=list(w.unlinks);failed=[];original=p.require
  def requirement(value):
   if not value:
    frame=inspect.currentframe().f_back;failed.append((frame.f_code.co_name,frame.f_lineno))
   return original(value)
  with patch.object(p,'require',requirement),self.assertRaisesRegex(p.Refused,'^policy-fence-refused$'):w.run()
  self.assertEqual(w.unlinks,unlinks);self.assertEqual(w.ledger.read_bytes(),before)
  self.assertTrue(any(name=='_fence' and 802<=line<=843 for name,line in failed),failed)
 def test_unchanged_intended_and_fenced_records_positive(self):
  with legacy_case() as w,Monitor(w) as monitor:
   stop_intended(w);w.run();self.assertEqual(len(w.unlinks),2);w.run();self.assertEqual(len(w.unlinks),2)
   self.assertEqual(len(w.read()[p.KEY]),14);self.assertEqual(len(set(w.read()[p.KEY]['intendedEpochs'])),6)
   self.assertEqual(monitor.live,{})
 def test_every_nested_saved_record_integer_float_alias_is_rejected(self):
  # Full recursive sweep, not just the three native C40 parent examples.
  with legacy_case() as sample:
   stop_intended(sample);paths=list(numeric_paths(sample.read()[p.KEY]))
  self.assertGreaterEqual(len(paths),50)
  for path,_ in paths:
   with self.subTest(path=path),legacy_case() as w:
    stop_intended(w);state=w.read();before=copy.deepcopy(state[p.KEY]);current=state[p.KEY]
    for key in path:current=current[key]
    put(state[p.KEY],path,float(current))
    self.assertEqual(state[p.KEY],before);self.assertNotEqual(p.canonical(state[p.KEY]),p.canonical(before));self.strict(w,state)
 def test_every_nested_zero_one_boolean_alias_rejected_including_completed_records(self):
  for phase in ('intended','fenced'):
   with legacy_case() as sample:
    stop_intended(sample)
    if phase=='fenced':sample.run()
    paths=[path for path,value in numeric_paths(sample.read()[p.KEY]) if value in (0,1)]
   for path in paths:
    with self.subTest(phase=phase,path=path),legacy_case() as w:
     stop_intended(w)
     if phase=='fenced':w.run()
     state=w.read();before=copy.deepcopy(state[p.KEY]);value=state[p.KEY]
     for key in path:value=value[key]
     put(state[p.KEY],path,bool(value));self.assertEqual(state[p.KEY],before)
     self.assertNotEqual(p.canonical(state[p.KEY]),p.canonical(before));self.strict(w,state)
 def test_old_operation_hash_and_foreign_nested_binding_reject_before_resume(self):
  for kind in ('old-operation','directory-inode','lease-mode','second-parent','epoch'):
   with self.subTest(kind=kind),legacy_case() as w:
    stop_intended(w);state=w.read();record=state[p.KEY]
    if kind=='old-operation':record['operationSha256']='8c3d53d820e56de3fd171c994a9d61393d61dcdf702b527117c5de432e886135'
    if kind=='directory-inode':record['leaseIdentity']['directory']['ino']+=1
    if kind=='lease-mode':record['leaseIdentity']['file']['mode']^=0o100
    if kind=='second-parent':record['policies'][1]['parent']['ino']+=1
    if kind=='epoch':record['intendedEpochs'][0]='0'*64
    self.strict(w,state)
 def test_plan_nested_numeric_alias_does_not_match_authenticated_plan(self):
  with legacy_case() as w:
   state=w.read();state['plan']['accounts'][0]['uid']=float(state['plan']['accounts'][0]['uid']);w.save(state)
   self.assertEqual(state['plan'],w.plan);self.assertNotEqual(p.canonical(state['plan']),p.canonical(w.plan))
   with self.assertRaises(p.Refused):w.run()
   self.assertEqual(w.unlinks,[]);self.assertNotIn(p.KEY,w.read())
 def test_held_fds_and_owned_absence_continuation(self):
  for phase in ('sudo-issued','tmpfiles-issued'):
   with self.subTest(phase=phase),legacy_case() as w,Monitor(w) as monitor:
    w.fault='after-'+phase
    with self.assertRaises(p.Refused):w.run()
    count=len(w.unlinks);self.assertEqual(w.read()[p.KEY]['phase'],phase);self.assertEqual(monitor.live,{})
    w.fault=None;w.run();self.assertEqual(len(w.unlinks),2);self.assertEqual(count,1 if phase=='sudo-issued' else 2);self.assertEqual(monitor.live,{})

class ActualCodeTarget(unittest.TestCase):
 def test_closed_schema_config_maps_and_modes_before_any_source_load(self):
  kinds=('schema-bool','schema-float','root-dot-slash','root-parent','root-absolute','extra-key','lock-mode','code-commit','code-map','target-map','duplicate-generated','duplicate-artifact','cfg-bool','cfg-float','cfg-extra','row-mode-float','ledger-path','receipt-path')
  for kind in kinds:
   with self.subTest(kind=kind),a.World() as w:
    f=c.Fixture(w);profile=f.profile;cfg=profile['targetAuthority']['inputConfiguration']
    if kind=='schema-bool':profile['schemaVersion']=True
    if kind=='schema-float':profile['schemaVersion']=2.0
    if kind=='root-dot-slash':profile['codeRoot']='./'
    if kind=='root-parent':profile['codeRoot']='..'
    if kind=='root-absolute':profile['codeRoot']=str(f.root)
    if kind=='extra-key':profile['foreign']=False
    if kind=='code-commit':profile['codeAuthority']['generatorCommit']=p.TARGET_COMMIT
    if kind=='code-map':profile['codeAuthority']['ops'].pop(next(iter(profile['codeAuthority']['ops'])))
    if kind=='target-map':profile['targetAuthority']['ops'][next(iter(profile['targetAuthority']['ops']))]='0'*64
    if kind=='duplicate-generated':profile['targetAuthority']['generatedNames'][0]=profile['targetAuthority']['generatedNames'][1]
    if kind=='duplicate-artifact':profile['targetAuthority']['artifactFields'][0]=profile['targetAuthority']['artifactFields'][1]
    if kind=='cfg-bool':cfg['schemaVersion']=True
    if kind=='cfg-float':cfg['schemaVersion']=1.0
    if kind=='cfg-extra':cfg['foreign']=True
    if kind=='row-mode-float':cfg['ops'][next(iter(cfg['ops']))]['mode']=384.0
    if kind=='ledger-path':cfg['ledgerPath']=str(w.ledger/'..')
    if kind=='receipt-path':cfg['historicalArtifactReceiptPath']='relative'
    f.save()
    if kind=='lock-mode':(f.root/'SOURCE-LOCK.json').chmod(0o644)
    loaded=[]
    with patch.object(p,'load_closed',side_effect=lambda *args:loaded.append(args)),self.assertRaises(p.Refused):f.inputs()
    self.assertEqual(loaded,[]);self.assertEqual(w.unlinks,[]);self.assertNotIn(p.KEY,w.read())
 def test_registry_transitive_wrong_source_and_cache_close_before_first_import(self):
  for kind in ('registry','sibling','different-target-code','cache','extra-directory'):
   with self.subTest(kind=kind),a.World() as w:
    f=c.Fixture(w)
    if kind in ('registry','sibling'):
     name='venue-registry-images.py' if kind=='registry' else 'venue-unit-stage.py';path=f.root/name;path.write_bytes(path.read_bytes()+b'\n# PUBLIC independently changed dependency\n')
    if kind=='different-target-code':
     name='venue-start-quarantine.py';body=(c.R/'generator/target57'/name).read_bytes();self.assertNotEqual(body,(f.root/name).read_bytes());(f.root/name).write_bytes(body)
    if kind=='cache':(f.root/'__pycache__').mkdir();(f.root/'__pycache__/anything.pyc').write_bytes(b'PUBLIC never execute')
    if kind=='extra-directory':(f.root/'foreign').mkdir()
    result,events=f.context();self.assertIsNone(result);self.assertFalse(any(row.startswith('load:') for row in events),events)
 def test_original_generated_data_empty_and_over_code_size_accepted_without_loading(self):
  for size in (0,1048577):
   with self.subTest(size=size),a.World() as w:
    f=c.Fixture(w);name=next(iter(p.GENERATED_OPS));body=b'D'*size;(w.bundle/'ops'/name).write_bytes(body)
    f.profile['targetAuthority']['inputConfiguration']['ops'][name]['sha256']=p.sha(body);f.save()
    result,events=f.context();self.assertIsNotNone(result);self.assertEqual(result[4]['ops'],f.inputs()['opsSha256'])
    self.assertFalse(any(str(w.bundle/'ops') in event for event in events if event.startswith('load:')))
 def test_external_manifest_recursive_extra_body_and_controller_pin_close_before_lifecycle(self):
  for kind in ('extra','controller','manifest-body','nested-extra'):
   with self.subTest(kind=kind),a.World() as w:
    f=c.Fixture(w)
    if kind=='extra':(f.slot/'foreign.py').write_bytes(b'PUBLIC foreign')
    if kind=='controller':(f.slot/'p0_host_context.py').write_bytes(b'PUBLIC different controller')
    if kind=='manifest-body':(f.slot/'units'/p.HOST_UNITS[0]).write_bytes(b'PUBLIC different unit')
    if kind=='nested-extra':(f.slot/'units/foreign.py').write_bytes(b'PUBLIC extra nested code')
    result,events=f.context();self.assertIsNone(result)
    self.assertFalse(any(event.startswith('load:') and event.endswith('venue-start-quarantine.py') for event in events),events)
 def test_private_full_fence_and_late_code_change_before_intent(self):
  with a.World() as w:
   f=c.Fixture(w);result,events=f.context(full=True);self.assertIsNotNone(result)
   record=w.read()[p.KEY];self.assertEqual(record['operationSha256'],p.sha(Path(p.__file__).read_bytes()))
   self.assertEqual(record['sourceClosureSha256'],p.sha(p.canonical(c.REAL_CONTEXT.__globals__ and f.context()[0][4])))
   self.assertEqual(len(record['intendedEpochs']),6);self.assertEqual(len(w.unlinks),2)
  with a.World() as w:
   f=c.Fixture(w);old=p._policy_inputs;calls=[]
   def altered(*args):
    result=old(*args);calls.append(True)
    if len(calls)==1:
     file=f.root/'venue-registry-images.py';file.write_bytes(file.read_bytes()+b'\n# PUBLIC late code mutation\n')
    return result
   with patch.object(p,'_policy_inputs',side_effect=altered):result,events=f.context(full=True)
   self.assertIsNone(result);self.assertGreaterEqual(len(calls),2);self.assertNotIn(p.KEY,w.read());self.assertEqual(w.unlinks,[])
 def test_no_in_place_config_patch_and_prepost_cohort_hashes_differ(self):
  with a.World() as w:
   f=c.Fixture(w);before=f.inputs();self.assertIsNone(json.loads((c.R/'SOURCE-LOCK.template.json').read_text())['targetAuthority']['inputConfiguration'])
   original=f.profile['targetAuthority']['inputConfiguration']['initialReviewedLedgerSha256']
   f.profile['targetAuthority']['inputConfiguration']['initialReviewedLedgerSha256']='0'*64;f.save();after=f.inputs()
   self.assertEqual(before['code59Sha256'],after['code59Sha256']);self.assertNotEqual(before['flat61Sha256'],after['flat61Sha256'])
   self.assertNotEqual(original,'0'*64)
