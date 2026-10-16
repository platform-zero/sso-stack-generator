#!/usr/bin/env python3
"""Hostile static host-network listener fixtures; never a runtime proof."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('listener_intent',root/'runtime-generator/podman-ops/verify-existing-host-listener-intent.py')
intent=importlib.util.module_from_spec(spec);spec.loader.exec_module(intent)

class IntentTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.bundle=Path(t.name);rootful=self.bundle/'quadlet/rootful';rootful.mkdir(parents=True)
        apps=self.bundle/'quadlet/rootless-apps';apps.mkdir()
        caddy=self.bundle/'runtime/configs/caddy';caddy.mkdir(parents=True)
        (self.bundle/'podman-domains.json').write_text(json.dumps({'venue':{'unitPrefix':'p0test-r1'}}))
        self.units={name:rootful/f'p0test-r1-{name}.container' for name in ('alloy','caddy','node-exporter','ntfy-native-auth')}
        for path in self.units.values():path.write_text('[Container]\nNetwork=host\n')
        self.units['alloy'].write_text(self.units['alloy'].read_text()+'Exec="run" "--server.http.listen-addr=127.0.0.1:12345" "/etc/alloy/alloy.hcl"\n')
        self.units['node-exporter'].write_text(self.units['node-exporter'].read_text()+'Exec="--web.listen-address=127.0.0.1:9100"\n')
        self.auth=caddy/'ntfy-native-auth.py';self.auth.write_text('ThreadingHTTPServer(("127.0.0.1", 25017), Handler).serve_forever()\n')
        self.file=caddy/'Caddyfile';self.file.write_text('{\n{{CADDY_GLOBAL_OPTIONS}}\n}\n')
        self.livekit=apps/'p0test-r1-livekit.container';self.livekit.write_text('[Container]\nNetwork=p0test-r1-caddy.network\n')
    def test_only_four_classified_no_activation(self):
        proof=intent.verify(self.bundle)
        self.assertEqual(proof['hostNetworkCount'],4)
        self.assertFalse(proof['activationAuthorized'] or proof['livekitHostNetwork'])
    def test_hostile_bind_and_old_service_proposals_refuse(self):
        for error in ('alloy-wildcard','node-wildcard','ntfy-wildcard','caddy-template','livekit-host','extra-host','host-publisher'):
            self.setUp()
            if error=='alloy-wildcard':self.units['alloy'].write_text(self.units['alloy'].read_text().replace('127.0.0.1','0.0.0.0'))
            elif error=='node-wildcard':self.units['node-exporter'].write_text(self.units['node-exporter'].read_text().replace('127.0.0.1','0.0.0.0'))
            elif error=='ntfy-wildcard':self.auth.write_text(self.auth.read_text().replace('127.0.0.1','0.0.0.0'))
            elif error=='caddy-template':self.file.write_text('{{CADDY_GLOBAL_OPTIONS}}\n{{CADDY_GLOBAL_OPTIONS}}\n')
            elif error=='livekit-host':self.livekit.write_text('[Container]\nNetwork=host\n')
            elif error=='extra-host':(self.units['caddy'].parent/'p0test-r1-extra.container').write_text('[Container]\nNetwork=host\n')
            elif error=='host-publisher':self.units['alloy'].write_text(self.units['alloy'].read_text()+'PublishPort=0.0.0.0:56001:12345\n')
            with self.subTest(error=error),self.assertRaises(intent.Refusal):intent.verify(self.bundle)

if __name__=='__main__':unittest.main()
