#!/usr/bin/env python3
"""Focused original installer hook + source-model consumer integration.
No actual root/native engine/admin/service access; all subprocesses are fixtures.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT/'runtime-generator/podman-ops/install-podman-bundle.sh'
FINANCE = ROOT.parent/'module-delivery/keycloak/stack.config/keycloak/configure-finance.sh'
GATEWAY = ROOT.parent/'module-delivery/keycloak-auth-gateway/stack.runtime.yaml'
TESTS = ROOT.parent/'module-delivery/keycloak/tests'


def load_fixture(name, path):
    spec=importlib.util.spec_from_file_location(name,path); module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module; exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__); return module


class InstallerHooks(unittest.TestCase):
    def test_exact_hook_order_no_replay_or_normal_phase_edits(self):
        text=INSTALLER.read_text(); arm=text.index('--native-finance-arm'); capture=text.index('--native-finance-capture')
        self.assertLess(text.index('journal starting'),arm)
        self.assertLess(arm,text.index('systemctl --no-block restart webservices.target'))
        self.assertLess(text.index('user_systemctl "$i" --no-block restart webservices.target'),capture)
        self.assertLess(capture,text.index('\nwait_for_cross_domain_producers\n'))
        self.assertLess(capture,text.index('\njournal active\n'))
        a=text.index('# Arm only the selected finance native collector'); b=text.index('if [ "$STANDALONE" = false ]; then',a)
        c=text.index('# Capture the original LIVE configure CID'); d=text.index('wait_for_cross_domain_producers\n',c)
        restored=text[:a]+text[b:c]+text[d:]
        self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(),'571f4cc28973af2292a1f4a265585bcaedd2a8713f47e8f5eccf44fc02c9c412')
    def test_shell_hook_executes_only_selected_standalone(self):
        text=INSTALLER.read_text(); blocks=[]
        for flag in ('arm','capture'):
            pos=text.index('--native-finance-'+flag); a=text.rfind('if [ "$STANDALONE"',0,pos); b=text.index('\nfi',pos)+3
            blocks.append(text[a:b])
        for standalone,selected,expected in [('true',True,2),('true',False,0),('false',True,0)]:
            with self.subTest(standalone=standalone,selected=selected), tempfile.TemporaryDirectory() as tmp:
                out=Path(tmp)/'calls'; env=dict(os.environ,TRACE=str(out))
                body='set -euo pipefail\nSTANDALONE='+standalone+'\nrelease=/fixture/release\nSTATE_ROOT=/fixture/root\n'
                body+='jq() { return '+('0' if selected else '1')+'; }\n'
                body+='python3() { printf "%s\\n" "$*" >> "$TRACE"; }\n'+'\n'.join(blocks)
                result=subprocess.run(['bash','-c',body],env=env,capture_output=True,text=True,timeout=5)
                self.assertEqual(result.returncode,0,result.stderr)
                calls=out.read_text().splitlines() if out.exists() else []
                self.assertEqual(len(calls),expected)
                if expected:
                    self.assertTrue(calls[0].endswith('--native-finance-arm')); self.assertTrue(calls[1].endswith('--native-finance-capture'))
    def test_only_configure_has_readonly_root_metadata(self):
        text=GATEWAY.read_text(); prefix,daemon=text.split('  keycloak-auth-gateway:',1)
        self.assertIn('FIREFLY_NATIVE_OWNERSHIP_FILE: "/run/p0-finance/input.json"',prefix)
        self.assertIn('"/var/lib/webservices-native-finance:/run/p0-finance:ro"',prefix)
        self.assertNotIn('NATIVE_OWNERSHIP',daemon); self.assertNotIn('/run/p0-finance',daemon)
    def test_scripts_parse(self):
        for path in (INSTALLER,FINANCE):
            result=subprocess.run(['bash','-n',str(path)],capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)


# Existing source-model fixture is imported, never rewritten or counted as new
# native proof. Positive transport cases relocate ONLY /run constant and replace
# stat's Root ownership projection with a fixture stub. Actual parser/source gates
# and full finance parent/role/group model run unchanged in the emitted script.
sys.path.insert(0,str(TESTS))
retained=load_fixture('finance_transport_existing_fixture',TESTS/'test_retained_finance_owner.py')


class ConsumerTransport(unittest.TestCase):
    def setUp(self):
        self.fixture=retained.FinanceFixture(self)
        self.base=self.fixture.c.block.removesuffix('\n'+FINANCE.read_text())
    def input_file(self, native=None, **patch):
        c=self.fixture.c
        script=c.path/'transport-finance.sh'
        input_path=c.path/'root-input.json'
        source=FINANCE.read_text().replace('/run/p0-finance/input.json',str(input_path))
        namespace=c.path/'modeled-rootful-uid-map';namespace.write_text('0 0 4294967295\n')
        source=source.replace('/proc/self/uid_map',str(namespace))
        # Test-only stat projection. No attempt to create Root-owned host files.
        source=source.replace("$(stat -c '%u:%g:%a:%h' -- \"$finance_input\")",'0:0:444:1')
        script.write_text(source)
        domain=c.env['DOMAIN']; realm=c.env['REALM']
        value=dict(schemaVersion=1,kind='root-native-finance-input',root='/fixture/root',release='/fixture/root/releases/one',
                   intentSha256='a'*64,sourceSha256=hashlib.sha256(script.read_bytes()).hexdigest(),
                   issuer='https://keycloak.'+domain+'/realms/'+realm,status='retained' if native else 'fresh',nativeFinanceOwnership=native)
        value.update(patch); input_path.write_text(json.dumps(value))
        c.env['FIREFLY_NATIVE_OWNERSHIP_FILE']=str(input_path)
        return script,input_path
    def run_transport(self, script):
        # Same actual runtime canonical functions and owning fixture double.
        self.fixture.c.block=self.base+'\nsource '+str(script)+'\n'
        return self.fixture.call()
    def test_missing_production_reference_refuses(self):
        self.fixture.c.env['FIREFLY_NATIVE_OWNERSHIP_FILE']='/run/p0-finance/input.json'
        self.assertNotEqual(self.fixture.call().returncode,0)
        self.fixture.c.assert_no_mutations()
    def test_fresh_input_clears_manual_ids_but_keeps_original_post_gates(self):
        self.fixture.c.env.update(FIREFLY_IDENTITY_CLIENT_UUID=retained.uid(999),FIREFLY_IDENTITY_SERVICE_ACCOUNT_SUBJECT=retained.uid(998))
        script,_=self.input_file()
        result=self.run_transport(script)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('nativeFinanceOwnership=',result.stdout)
    def native_model_edge(self):
        # Synthetic NATIVE model relationship, NOT logger/stdout admission.
        state=self.fixture.c.state
        client=next(c for c in state['clients'] if c['clientId']=='firefly-identity-reader')
        return dict(clientId=client['clientId'],clientUuid=client['id'],serviceAccountSubject=state['serviceUsers'][client['id']]['id'])
    def test_retained_root_input_overrides_manual_ids_and_is_read_only(self):
        first=self.fixture.call(); self.assertEqual(first.returncode,0,first.stderr)
        native=self.native_model_edge()
        self.fixture.c.env.update(FIREFLY_IDENTITY_CLIENT_UUID=retained.uid(999),FIREFLY_IDENTITY_SERVICE_ACCOUNT_SUBJECT=retained.uid(998))
        self.fixture.c.state['argv']=[]
        script,_=self.input_file(native)
        result=self.run_transport(script); self.assertEqual(result.returncode,0,result.stderr)
        self.fixture.c.assert_no_mutations()
        self.assertFalse(any(a[1].endswith('/service-account-user') for a in self.fixture.c.state['argv']))
    def test_fresh_root_input_never_adopts_retained_clients(self):
        first=self.fixture.call(); self.assertEqual(first.returncode,0,first.stderr)
        self.fixture.c.state['argv']=[]
        script,_=self.input_file()
        self.assertNotEqual(self.run_transport(script).returncode,0); self.fixture.c.assert_no_mutations()
    def test_wrong_source_issuer_kind_or_extra_field_refuses_before_native_calls(self):
        for patch in ({'sourceSha256':'b'*64},{'issuer':'https://foreign.invalid'},{'kind':'logger-json'},{'approval':True}):
            with self.subTest(patch=patch):
                script,_=self.input_file(**patch)
                self.assertNotEqual(self.run_transport(script).returncode,0)
                self.assertEqual(self.fixture.c.state['argv'],[])
    def test_duplicate_json_key_refuses_before_native_calls(self):
        script,path=self.input_file(); text=path.read_text(); path.write_text(text[:-1]+',"status":"retained"}')
        self.assertNotEqual(self.run_transport(script).returncode,0); self.assertEqual(self.fixture.c.state['argv'],[])
    def test_missing_retained_edge_refuses_without_autocreating_get(self):
        script,_=self.input_file(status='retained')
        self.assertNotEqual(self.run_transport(script).returncode,0); self.assertEqual(self.fixture.c.state['argv'],[])


if __name__=='__main__': unittest.main(verbosity=2)
