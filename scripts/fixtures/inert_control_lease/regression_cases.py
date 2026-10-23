import ast,hashlib,inspect,json,os,pathlib,sys,types,unittest
from unittest.mock import patch
import inert_control_lease_native as m
import test_native_lease as original
HERE=pathlib.Path(__file__).resolve().parent
class ActualUser(unittest.TestCase):
 def test_actual_user_default_refuses_before_kernel_private_reads(self):
  self.assertNotEqual(os.geteuid(),0)
  with patch.object(m,'_kernel',side_effect=AssertionError('unexpected kernel access')),patch.object(m,'_retire',side_effect=AssertionError('unexpected dispatch')):
   with self.assertRaisesRegex(m.Refused,'^root-admission$'):
    m.retire_inert_control_lease('/public/bundle','/public/selector','/public/ledger','a'*64,'b'*64,'c'*64)

class Review(original.NativeTests):
 def outcome(self):
  try:return self.run_api()['status']
  except m.Refused as e:return 'REFUSED:'+str(e)
 def refuse_without_deletion(self):
  result=self.outcome()
  self.assertTrue(result.startswith('REFUSED:'),result+'; unlink='+str(self.events('unlink'))+'; rmdir='+str(self.events('rmdir')))
  self.assertEqual(self.events('unlink'),[])
 
 def r_missing_complete_fence_fields_should_refuse(self):
  # Unchanged producer positive contains eight fields; final fc98 also
  # requires ledgerPath/ledgerParent/leaseIdentity/policies/epochs/before-CAS.
  self.assertEqual(set(self.data()[m.FENCE]),{'schemaVersion','phase','namespace','hostContextSha256','provenanceSha256','planSha256','operationSha256','sourceClosureSha256'})
  self.refuse_without_deletion()
 def r_invalid_fence_policy_history_should_refuse(self):
  self.mutate(lambda s:s[m.FENCE].update(policies=[],intendedEpochs=[],ledgerSha256Before='not-a-hash'))
  self.refuse_without_deletion()
 def r_foreign_fence_lease_identity_should_refuse(self):
  self.mutate(lambda s:s[m.FENCE].update(leaseIdentity={'directory':{'ino':999999},'file':{'ino':999999}}))
  self.refuse_without_deletion()
 def r_wrong_fence_ledger_path_should_refuse(self):
  self.mutate(lambda s:s[m.FENCE].update(ledgerPath='/foreign/ledger.json',ledgerParent={'ino':999999}))
  self.refuse_without_deletion()
 def r_host_unit_hash_mismatch_should_refuse(self):
  self.mutate(lambda s:s['venueHostUnitsRetirement']['units'][0].update(sha256='e'*64))
  self.refuse_without_deletion()
 def r_nonzero_effective_gid_should_refuse_before_source_load(self):
  with patch.object(self.fs,'getegid',return_value=1000,create=True):self.refuse_without_deletion()
 def r_different_pid_namespace_should_refuse_before_source_load(self):
  self.namespace_mismatch('pid')
 def r_different_mount_namespace_should_refuse_before_source_load(self):
  self.namespace_mismatch('mnt')
 def namespace_mismatch(self,kind):
  previous=self.fs.stat
  def observed(p,*a,**kw):
   if str(p)=='/proc/self/ns/'+kind:return types.SimpleNamespace(st_dev=9,st_ino=101)
   if str(p)=='/proc/1/ns/'+kind:return types.SimpleNamespace(st_dev=9,st_ino=202)
   return previous(p,*a,**kw)
  with patch.object(self.fs,'stat',observed):self.refuse_without_deletion()
 def r_false_activation_integer_is_rejected(self):
  self.mutate(lambda s:s.update(activationAuthorized=0));self.refuse_without_deletion()
 def r_duplicate_json_is_rejected(self):
  self.fs.nodes[self.ledger].data=b'{"plan":{},"plan":{}}';self.refuse_without_deletion()
 def r_negative_overflow_is_rejected(self):
  self.fs.nodes[self.ledger].data=b'{"plan":-1e999}';self.refuse_without_deletion()
 def r_unknown_pending_false_is_not_ignored(self):
  self.mutate(lambda s:s.update(otherPending=False));self.refuse_without_deletion()
 def r_typed_history_bool_is_rejected(self):
  h,v=self.history();h['schemaVersion']=True
  self.mutate(lambda s:s.update(venueRegistryFailedPendingRetirement=h,venueRegistryPlan=self.images,venueRegistryVerified=v,venueRegistryPreparationAbandoned=True))
  self.refuse_without_deletion()
 def r_conditional_writer_after_final_check_foreign_lease_preserved(self):
  # CONDITIONAL ONLY: explicitly violates external ALL-root-writers exclusion.
  # Demonstrates real stat/unlink cannot be called inode CAS / rollback.
  previous=m._Native.read_ledger;foreign=[]
  def reading(native):
   result=previous(native)
   if inspect.currentframe().f_back.f_code.co_name=='unlink' and not foreign:
    old=self.fs.nodes[self.runtime+'/lifecycle.lock'];old.linked=False
    foreign.append(self.fs.put(self.runtime+'/lifecycle.lock',__import__('stat').S_IFREG|0o600))
   return result
  with patch.object(m._Native,'read_ledger',reading):result=self.outcome()
  self.assertEqual(len(foreign),1)
  (HERE/'CONDITIONAL-WRITER-REPRO.json').write_text(json.dumps({'result':result,'foreignPreserved':foreign[0].linked,'unlink':self.events('unlink'),'rmdir':self.events('rmdir'),'exclusionViolated':True},indent=2)+'\n')
  self.assertTrue(foreign[0].linked,'conditional foreign lease deleted after final read; '+result)
