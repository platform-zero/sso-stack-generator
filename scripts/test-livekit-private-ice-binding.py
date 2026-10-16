#!/usr/bin/env python3
"""Fail-closed private ICE port and node binding without running Livekit."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('private_livekit',root/'runtime-generator/podman-ops/bind-livekit-venue-ports.py')
livekit=importlib.util.module_from_spec(spec);spec.loader.exec_module(livekit)

class PrivateIceTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.bundle=Path(tmp.name);(self.bundle/'site').mkdir()
        self.guest={'networkConfig':{'address':'192.168.140.115/24','gateway':'192.168.140.1','nameservers':['192.168.140.1']}}
        self.map={'7881':56049,'7882':56050};self.source=b'port: 7880\nrtc:\n  node_ip: "192.168.140.1"\n  tcp_port: 7881\n  udp_port: 7882\n'
        self.config=self.bundle/'livekit.yaml';self.config.write_bytes(self.source);self.config.chmod(0o644)
        self.save()
    def save(self):
        (self.bundle/'site/agent-vm.json').write_text(json.dumps(self.guest))
        (self.bundle/'podman-domains.json').write_text(json.dumps({'venue':{'unitPrefix':'p0test-r1','portMap':self.map}}))
    def test_exact_ice_advertisement_and_idempotence(self):
        self.assertTrue(livekit.bind(self.bundle,self.config)['changed'])
        self.assertIn(b'tcp_port: 56049\n  udp_port: 56050',self.config.read_bytes())
        self.assertFalse(livekit.bind(self.bundle,self.config)['changed'])
        self.assertNotIn(b'node_ip: "192.168.0.11"',self.config.read_bytes())
    def test_source_and_gateway_drift_refused_without_write(self):
        for kind in ('old-guest','gateway','wildcard','duplicate','stale-ice','same-port','linked'):
            self.map={'7881':56049,'7882':56050}
            self.guest['networkConfig']={'address':'192.168.140.115/24','gateway':'192.168.140.1','nameservers':['192.168.140.1']}
            self.config.unlink(missing_ok=True);self.config.write_bytes(self.source);self.config.chmod(0o644)
            if kind=='old-guest':self.guest['networkConfig']['address']='192.168.122.235/24'
            if kind=='gateway':self.guest['networkConfig']['gateway']='192.168.122.1'
            if kind=='wildcard':self.config.write_bytes(self.source.replace(b'192.168.140.1',b'192.168.0.11'))
            if kind=='duplicate':self.config.write_bytes(self.source+self.source)
            if kind=='stale-ice':self.config.write_bytes(self.source.replace(b'tcp_port: 7881',b'tcp_port: 7883'))
            if kind=='same-port':self.map['7882']=56049
            if kind=='linked':self.config.unlink();self.config.symlink_to(self.bundle/'site/agent-vm.json')
            self.save();original=self.config.read_bytes()
            with self.subTest(kind=kind),self.assertRaises((livekit.Refusal,ValueError)):
                livekit.bind(self.bundle,self.config)
            self.assertEqual(self.config.read_bytes(),original)

if __name__=='__main__':unittest.main()
