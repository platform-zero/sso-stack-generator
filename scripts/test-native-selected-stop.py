#!/usr/bin/env python3
"""Extract actual shell stop/cancel helpers; subprocess boundary models only."""
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/install-podman-bundle.sh'
text=SOURCE.read_text()
def function(name):
 start=text.index(name+'() {');end=text.index('\n}\n',start)+3
 return text[start:end]
FUNCTIONS='\n'.join(function(name) for name in ('native_stop_units','stop_selected_services','cancel_webservices_start_jobs'))
BASE=r'''
set -eu
STANDALONE=true
ROOTLESS_DOMAIN_NAMES=(platform apps homeassistant finance ci-runner workloads test-runners)
release=/candidate
STATE_ROOT=/metadata
python3() {
 printf 'selector %s\n' "$*" >> "$TRACE"
 [ "${FAIL_SELECT:-0}" = 0 ] || return 19
 [ "${EMPTY:-0}" = 0 ] || return 0
 printf '%s\n' webservices-one.service webservices-net-network.service webservices.target
}
selected_container_units() { printf 'UNSAFE PREFIX FALLBACK\n' >> "$TRACE"; return 29; }
run_systemctl() {
 printf 'systemctl %s\n' "$*" >> "$TRACE"
 if [ "$1" = list-jobs ]; then
   [ "${FAIL_LIST:-0}" = 0 ] || return 23
   printf '%s\n' '21 webservices-one.service start waiting' '22 webservices-one.service stop waiting' '23 webservices-foreign.service start waiting' '24 unrelated.service start waiting' '25 webservices-net-network.service start waiting'
 fi
 if [ "$1" = cancel ] && [ "${FAIL_CANCEL:-0}" != 0 ]; then return 31; fi
}
systemctl() { run_systemctl "$@"; }
user_systemctl() { printf 'actor-index %s\n' "$1" >> "$TRACE"; shift;run_systemctl "$@"; }
'''
class ExactStop(unittest.TestCase):
 def run_model(self,body):
  with tempfile.TemporaryDirectory() as temp:
   trace=Path(temp)/'trace';trace.touch()
   script='TRACE='+str(trace)+'\n'+BASE+'\n'+FUNCTIONS+'\n'+body
   result=subprocess.run(['bash','-c',script],capture_output=True,text=True,timeout=5)
   return result,trace.read_text()
 def test_stop_all_owned_service_network_and_target(self):
  result,trace=self.run_model('stop_selected_services rootful 0 /unused')
  self.assertEqual(result.returncode,0,result.stderr)
  self.assertIn('systemctl stop webservices-one.service webservices-net-network.service webservices.target',trace)
  self.assertNotIn('UNSAFE',trace)
 def test_actor_scope_is_exact(self):
  result,trace=self.run_model('stop_selected_services rootless 3 /unused')
  self.assertEqual(result.returncode,0,result.stderr);self.assertIn('--stop-selection --scope rootless-finance',trace)
  self.assertIn('actor-index 3',trace)
 def test_cancel_owned_non_stop_jobs_only(self):
  result,trace=self.run_model('cancel_webservices_start_jobs rootful 0')
  self.assertEqual(result.returncode,0,result.stderr);self.assertIn('systemctl cancel 21 25\n',trace)
  self.assertNotIn('cancel 22',trace);self.assertNotIn('cancel 23',trace)
 def test_selector_refusal_prevents_stop(self):
  result,trace=self.run_model('FAIL_SELECT=1;stop_selected_services rootful 0 /unused')
  self.assertNotEqual(result.returncode,0);self.assertNotIn('systemctl ',trace)
 def test_selector_refusal_prevents_cancel_and_job_query(self):
  result,trace=self.run_model('FAIL_SELECT=1;cancel_webservices_start_jobs rootless 3')
  self.assertNotEqual(result.returncode,0);self.assertNotIn('systemctl ',trace)
 def test_job_query_failure_not_hidden(self):
  result,trace=self.run_model('FAIL_LIST=1;cancel_webservices_start_jobs rootful 0')
  self.assertNotEqual(result.returncode,0);self.assertNotIn('systemctl cancel',trace)
 def test_cancel_failure_not_hidden(self):
  result,trace=self.run_model('FAIL_CANCEL=1;cancel_webservices_start_jobs rootful 0')
  self.assertNotEqual(result.returncode,0);self.assertIn('systemctl cancel 21 25',trace)
 def test_empty_selection_does_not_stop(self):
  result,trace=self.run_model('EMPTY=1;stop_selected_services rootful 0 /unused')
  self.assertEqual(result.returncode,0,result.stderr);self.assertNotIn('systemctl stop',trace)

if __name__=='__main__':unittest.main()
