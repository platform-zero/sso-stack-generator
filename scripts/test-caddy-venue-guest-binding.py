#!/usr/bin/env python3
"""Hostile native rerender fixtures: old guest must never reappear."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('bind_venue_guest',root/'runtime-generator/podman-ops/bind-caddy-venue-guest.py')
binding=importlib.util.module_from_spec(spec);spec.loader.exec_module(binding)

class GuestBindingTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.base=Path(tmp.name);(self.base/'site').mkdir()
        self.guest={'name':'p0-venue-r1-agents','networkConfig':{'address':'192.168.140.115/24',
                    'gateway':'192.168.140.1','nameservers':['192.168.140.1']}}
        self.venue={'unitPrefix':'p0test-r1','portMap':{'443':56042,'7880':56048}}
        self.caddy=self.base/'Caddyfile';self.old=binding.OLD+b'\nreverse_proxy host.containers.internal:7880\n'
        self.caddy.write_bytes(self.old);self.caddy.chmod(0o644);self.save()
    def save(self):
        (self.base/'site/agent-vm.json').write_text(json.dumps(self.guest))
        (self.base/'podman-domains.json').write_text(json.dumps({'venue':self.venue}))
    def test_rewrite_is_exact_idempotent_and_never_edits_source_or_legacy(self):
        first=binding.bind(self.base,self.caddy)
        self.assertTrue(first['changed']);self.assertFalse(first['activationAuthorized'])
        expected=b'reverse_proxy 192.168.140.115:24838\nreverse_proxy 127.0.0.1:56048\n'+binding.HTTP_REDIRECT
        self.assertEqual(self.caddy.read_bytes(),expected)
        self.assertFalse(binding.bind(self.base,self.caddy)['changed'])
        self.assertEqual(self.caddy.read_bytes(),expected)
    def test_bypass_and_mixed_input_refused_before_rewrite(self):
        for error in ('old-name','gateway','address','outside','metadata','port','livekit-port','duplicate','unexpected','redirect','linked'):
            self.guest['name']='p0-venue-r1-agents'
            self.guest['networkConfig']={'address':'192.168.140.115/24','gateway':'192.168.140.1','nameservers':['192.168.140.1']}
            self.venue={'unitPrefix':'p0test-r1','portMap':{'443':56042,'7880':56048}}
            self.caddy.unlink(missing_ok=True);self.caddy.write_bytes(self.old);self.caddy.chmod(0o644)
            if error=='old-name':self.guest['name']='p0-agents'
            if error=='gateway':self.guest['networkConfig']['gateway']='192.168.122.1'
            if error=='address':self.guest['networkConfig']['address']='192.168.122.235/24'
            if error=='outside':self.guest['networkConfig']['address']='192.168.140.1/24'
            if error=='metadata':self.venue['unitPrefix']='webservices'
            if error=='port':self.venue['portMap']['443']=443
            if error=='livekit-port':self.venue['portMap']['7880']=56042
            if error=='duplicate':self.caddy.write_bytes(self.old*2)
            if error=='unexpected':self.caddy.write_bytes(b'reverse_proxy 10.10.0.1:24838\n')
            if error=='redirect':self.caddy.write_bytes(self.old+b'http://{$DOMAIN} {\n\trespond 200\n}\n')
            if error=='linked':self.caddy.unlink();self.caddy.symlink_to(self.base/'site/agent-vm.json')
            self.save()
            before=(self.base/'site/agent-vm.json').read_bytes()
            with self.subTest(error=error),self.assertRaises((binding.Refusal,ValueError)):
                binding.bind(self.base,self.caddy)
            self.assertEqual((self.base/'site/agent-vm.json').read_bytes(),before)
            if error not in ('unexpected','duplicate','redirect','linked'):self.assertEqual(self.caddy.read_bytes(),self.old)

if __name__=='__main__':unittest.main()
