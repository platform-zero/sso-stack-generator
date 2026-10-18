#!/usr/bin/env python3
"""Synthetic hook ordering/refusal tests; never installed/native boot evidence."""
import hashlib,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
s=importlib.util.spec_from_file_location('guest_fence_hook',Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-guest-fence-hook.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
@unittest.skipUnless(os.geteuid()==0,'root-owned hook/proof fixtures')
class Hook(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory(prefix='p0-fence-unit-',dir='/run');self.addCleanup(t.cleanup);self.root=Path(t.name);self.root.chmod(0o700)
  self.source=self.root/'hook';self.source.write_text('# synthetic fixture\n');self.source.chmod(0o755)
  self.xml='<network><name>selected</name><uuid>exact-uuid</uuid><bridge name="private"/></network>'
  self.current={'nftables':[{'metainfo':{'version':'test'}},{'table':{'family':'inet','name':'selected_fence','handle':3}},{'chain':{'name':'guest','family':'inet','table':'selected_fence','handle':9,'prio':-50}}]}
  self.policy={'network':'selected','uuid':'exact-uuid','namespace':'p0test-r1','table':'selected_fence','networkXmlFingerprint':m.xml_fingerprint(m.ET.fromstring(self.xml)),
               'nftables':'table inet selected_fence {}\n','nativeFenceFingerprint':m.json_fingerprint(self.current),'proofPath':str(self.root/'proof.json')}
  self.policy['nftablesSha256']=hashlib.sha256(self.policy['nftables'].encode()).hexdigest();self.present=False;self.commands=[]
  p=patch.object(m,'native',side_effect=self.native);p.start();self.addCleanup(p.stop)
 def native(self,command,**kwargs):
  self.commands.append(command);self.assertEqual(command[0],'/usr/sbin/nft');self.assertNotIn('flush',command)
  if command[-2:]==['list','tables']:return json.dumps({'nftables':[{'table':{'family':'inet','name':'selected_fence'}}] if self.present else []})
  if '-c' in command:return ''
  if '-f' in command:self.present=True;return ''
  if 'list' in command:return json.dumps(self.current)
  self.fail('unexpected native command')
 def guard(self,args=None,xml=None):return m.guard(self.policy,args or ['selected','start','begin','-'],'<hookData>'+self.xml+'</hookData>' if xml is None else xml,source=self.source)
 def test_unrelated_network_passes_without_native_calls_or_xml_parsing(self):
  self.assertEqual(self.guard(['original','start','begin','-'],xml='not xml')['status'],'unrelated-network');self.assertFalse(self.commands)
 def test_stop_event_is_not_blocked_or_modified(self):
  self.assertEqual(self.guard(['selected','stopped','end','-'])['status'],'non-start-event');self.assertFalse(self.commands)
 def test_fence_check_precedes_apply_and_current_boot_proof(self):
  self.assertEqual(self.guard()['status'],'selected-network-fenced')
  self.assertIn('-c',self.commands[1]);self.assertNotIn('-c',self.commands[2]);proof=json.loads((self.root/'proof.json').read_text())
  self.assertEqual(proof['networkUuid'],'exact-uuid');self.assertFalse(proof['activationAuthorized']);self.assertEqual((self.root/'proof.json').stat().st_mode&0o777,0o600)
 def test_matching_existing_table_is_not_replaced_or_applied(self):
  self.present=True;self.guard();self.assertFalse(any('-f' in cmd for cmd in self.commands))
 def test_foreign_changed_table_refuses_without_flush_or_replacement(self):
  self.present=True;self.current['nftables'][2]['chain']['prio']=0
  with self.assertRaises(m.Refusal):self.guard()
  self.assertFalse((self.root/'proof.json').exists());self.assertFalse(any('-f' in cmd for cmd in self.commands))
 def test_changed_network_uuid_refuses_before_native_operation(self):
  self.xml=self.xml.replace('exact-uuid','foreign')
  with self.assertRaises(m.Refusal):self.guard()
  self.assertFalse(self.commands)
 def test_world_writable_installed_hook_refuses(self):
  self.source.chmod(0o777)
  with self.assertRaises(m.Refusal):self.guard()
  self.assertFalse(self.commands)
 def test_embedded_policy_tampering_refuses(self):
  self.policy['nftables']+='changed'
  with self.assertRaises(m.Refusal):self.guard()
  self.assertFalse(self.commands)
 def test_unknown_existing_proof_is_preserved(self):
  proof=self.root/'proof.json';proof.write_text('{"human":"authored"}');proof.chmod(0o600);self.present=True
  with self.assertRaises(m.Refusal):self.guard()
  self.assertEqual(proof.read_text(),'{"human":"authored"}');self.assertFalse(any('-f' in cmd for cmd in self.commands))
 def test_matching_proof_can_be_refreshed_without_applying_fence(self):
  self.guard();self.commands=[];self.guard();self.assertFalse(any('-f' in cmd for cmd in self.commands))
 def test_kernel_handles_and_version_are_not_rule_semantics(self):
  previous=m.json_fingerprint(self.current);self.current['nftables'][0]['metainfo']['version']='other';self.current['nftables'][1]['table']['handle']=450
  self.assertEqual(previous,m.json_fingerprint(self.current));self.current['nftables'][2]['chain']['prio']=1;self.assertNotEqual(previous,m.json_fingerprint(self.current))
 def test_xml_whitespace_and_connection_count_do_not_change_definition(self):
  other=m.ET.fromstring('<network connections="2">\n <name>selected</name><uuid>exact-uuid</uuid><bridge name="private"/>\n</network>')
  self.assertEqual(m.xml_fingerprint(other),self.policy['networkXmlFingerprint'])
if __name__=='__main__':unittest.main()
