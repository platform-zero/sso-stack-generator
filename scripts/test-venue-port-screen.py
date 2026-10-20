#!/usr/bin/env python3
"""Closed ephemeral TCP is not a live service; live/unknown occupancy still refuses."""
import importlib.util,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
OPS=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops'
def load(name,file):
 spec=importlib.util.spec_from_file_location(name,OPS/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('port_screen_fixture','verify-existing-host-venue.py')
class Ports(unittest.TestCase):
 def run_screen(self,protocol='tcp',state='06',inode='0',port=56010,extra=''):
  row='0: 0B00A8C0:'+format(port,'04X')+' F30042AC:01BB '+state+' 00000000:00000000 03:00001000 00000000 0 0 '+inode+'\n'
  def read(path,*args,**kwargs):return 'header\n'+(row+extra if str(path)=='/proc/net/'+protocol else '')
  with patch.object(Path,'read_text',read):m.port_screen({'ports':{'mariadb':56010}})
 def test_closed_ipv4_outbound_ephemeral_port_does_not_claim_listener(self):self.run_screen()
 def test_closed_ipv6_outbound_ephemeral_port_does_not_claim_listener(self):self.run_screen(protocol='tcp6')
 def test_listening_tcp_still_refuses(self):
  with self.assertRaises(m.Refusal):self.run_screen(state='0A',inode='123')
 def test_established_tcp_still_refuses(self):
  with self.assertRaises(m.Refusal):self.run_screen(state='01',inode='123')
 def test_timewait_with_owner_inode_still_refuses(self):
  with self.assertRaises(m.Refusal):self.run_screen(inode='123')
 def test_udp_never_treated_as_closed_tcp(self):
  with self.assertRaises(m.Refusal):self.run_screen(protocol='udp')
 def test_unknown_tcp_state_still_refuses(self):
  with self.assertRaises(m.Refusal):self.run_screen(state='FF')
 def test_other_live_row_cannot_hide_behind_timewait(self):
  with self.assertRaises(m.Refusal):self.run_screen(extra='1: 00000000:DACA 00000000:0000 0A 0 0 0 0 0 456\n')
 def test_unselected_socket_is_not_a_collision(self):self.run_screen(state='0A',inode='123',port=60001)
 def test_malformed_table_refuses(self):
  with patch.object(Path,'read_text',return_value='header\n0: 0000:DACA 0000:0000 06\n'):
   with self.assertRaises(m.Refusal):m.port_screen({'ports':{'mariadb':56010}})
 def test_unreadable_table_is_not_empty(self):
  with patch.object(Path,'read_text',side_effect=PermissionError('fixture')):
   with self.assertRaises(PermissionError):m.port_screen({'ports':{'mariadb':56010}})
 def test_diagnostic_preserves_the_actual_preflight_refusal(self):
  diagnostic=load('post_listener_port_fixture','inspect-existing-host-venue-beyond-listeners.py')
  with tempfile.TemporaryDirectory() as directory:
   selector=Path(directory)/'selector.json';selector.write_text(json.dumps({'unitPrefix':'p0test-r1'}))
   with patch.object(diagnostic,'load',return_value=NS(Refusal=ValueError)),patch.object(diagnostic.subprocess,'run',return_value=NS(returncode=1,stderr='venue preflight refused: port in use on host',stdout='')):
    with self.assertRaisesRegex(ValueError,'preflight exit=1; venue preflight refused: port in use on host'):diagnostic.inspect(directory,selector,'inventory')
if __name__=='__main__':unittest.main()
