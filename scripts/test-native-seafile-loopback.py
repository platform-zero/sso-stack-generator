#!/usr/bin/env python3
"""Temporary socketpair/source tests; no host TCP listener or native admission."""
import importlib.util
import json
from pathlib import Path
import socket
import sys
import threading
import unittest
from unittest.mock import patch

source=Path(__file__).parents[1]/'runtime-generator/podman-ops/native-seafile-loopback.py'
spec=importlib.util.spec_from_file_location('seafile_loopback_source_test',source)
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class PrivateRelay(unittest.TestCase):
 def test_opaque_bytes_bidirectional_over_bounded_socketpairs(self):
  client,front=socket.socketpair();upstream,server=socket.socketpair()
  self.addCleanup(client.close);self.addCleanup(server.close)
  client.settimeout(2);server.settimeout(2)
  with patch.object(r.socket,'create_connection',return_value=upstream) as connect:
   thread=threading.Thread(target=r.connection,args=(front,3306),daemon=True);thread.start()
   client.sendall(b'fixture-native-request');self.assertEqual(server.recv(64),b'fixture-native-request')
   server.sendall(b'fixture-native-response');self.assertEqual(client.recv(64),b'fixture-native-response')
   client.close();thread.join(timeout=2);self.assertFalse(thread.is_alive())
   connect.assert_called_once_with(('127.0.0.1',3306),timeout=5)
 def test_backend_unavailable_closes_source_without_echo_or_retry(self):
  client,front=socket.socketpair();self.addCleanup(client.close);client.settimeout(2)
  with patch.object(r.socket,'create_connection',side_effect=OSError('private-fixture-sentinel')) as connect:
   r.connection(front,6379)
   self.assertEqual(client.recv(1),b'');self.assertEqual(connect.call_count,1)
 def test_privileged_operator_or_invalid_route_refuses_before_socket_creation(self):
  invalid=[[[25003,1]],[[80,3306]],[[25003,3306],[25003,6379]],[[3306,3306]],{'host':'outside'},[[25003,3306],[25004,6379],[25005,6379]]]
  for uid,pairs in [(0,[[25003,3306]]),(1000,[[25003,3306]]),*[(780,pairs) for pairs in invalid]]:
   with self.subTest(uid=uid,pairs=pairs),patch.object(r.os,'getuid',return_value=uid),patch.object(sys,'argv',['relay',json.dumps(pairs)]),patch.object(r.socket,'socket') as opening:
    with self.assertRaises(AssertionError):r.main()
    opening.assert_not_called()

if __name__=='__main__':unittest.main()
