#!/usr/bin/env python3
"""Isolated synthetic Root/native model tests; NOT installed/native origin proof."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'runtime-generator/podman-ops/native-finance-ownership.py'
spec = importlib.util.spec_from_file_location('finance_model', SOURCE)
m = importlib.util.module_from_spec(spec); sys.modules[spec.name] = m
exec(compile(SOURCE.read_bytes(), str(SOURCE), 'exec'), m.__dict__)


def uid(i): return f'00000000-0000-4000-8000-{i:012x}'
EDGE = dict(clientId='firefly-identity-reader', clientUuid=uid(1), serviceAccountSubject=uid(2))
ISSUER = 'https://keycloak.example.invalid/realms/webservices'
CONFIG = dict(source='/etc/containers/systemd/webservices-keycloak-configure.container', sourceSha256='a'*64,
              fragment='/run/systemd/generator/webservices-keycloak-configure.service', fragmentSha256='b'*64,
              image='sha256:'+'c'*64)
SOURCE_PIN = dict(configure=CONFIG, postgres=dict(CONFIG, sourceSha256='d'*64), keycloak=dict(CONFIG, sourceSha256='e'*64),
                  financeScriptSha256=m.FINANCE_SOURCE_SHA256, runtimeScriptSha256='f'*64)
ORIGINAL = dict(kind=m.ORIGIN_KIND, bootId=uid(3), invocationId='1'*32, startMonotonicUSec=1, exitMonotonicUSec=2,
                container=dict(id='1'*64, image=CONFIG['image'], source=CONFIG, conmon={'pid':42,'cgroup':'/system.slice/webservices-keycloak-configure.service'}),
                database=dict(kind='keycloak-postgres-native-service-account-link', containerId='2'*64,
                              image='sha256:'+'d'*64, source=SOURCE_PIN['postgres'], querySha256=m.sha(m.SQL.encode()),
                              rowSha256=m.sha(m.encoded(EDGE))))


def receipt():
    return dict(schemaVersion=1, kind='root-native-finance-ownership', status='completed', release='/root-meta/releases/old',
                inputs={'fixture':'source-only'}, intentSha256='a'*64, custodySha256='b'*64, issuer=ISSUER, source=copy.deepcopy(SOURCE_PIN),
                original=copy.deepcopy(ORIGINAL), nativeFinanceOwnership=copy.deepcopy(EDGE),
                activationAuthorized=False, readinessAuthorized=False, journalWritten=False)


class FakeSelection:
    def snapshot(self): return dict(self.backend.binding, intentSha256=self.cas)
    def installed_sources(self): return True


class FakeNative:
    next_edge = EDGE
    def __init__(self, root, release, old):
        self.root, self.release, self.old = Path(root), Path(release), old
        self.source = copy.deepcopy(SOURCE_PIN); self.issuer = ISSUER; self.cas = 'f'*64; self.boot = uid(3)
        self.descriptor = dict(kind='native-finance-reference-descriptor',source=str(m.SLOT))
        self.publisher = dict(path='ops/native-finance-ownership.py',sha256='a'*64,origin='root-native-finance-ownership')
        self.binding = dict(intentSha256=self.cas, fixture='NOT NATIVE PROOF')
        self.selection = FakeSelection(); self.selection.backend = self; self.selection.cas = self.cas
        self.observed = False; self.exported = False
    def props(self, name): return dict(ActiveState='inactive', SubState='dead', Job='', InvocationID='')
    def recheck(self): pass
    def observe_original(self, custody): self.observed = True; return {k:v for k,v in copy.deepcopy(ORIGINAL).items() if k != 'database'}
    def export_edge(self): self.exported = True; return copy.deepcopy(self.next_edge), copy.deepcopy(ORIGINAL['database'])


class RootModel(unittest.TestCase):
    def setUp(self):
        self.root = Path('/root-meta'); self.release = self.root/'releases/selected'
        self.old = dict(schemaVersion=1, phase='starting', release=str(self.release), inputs={'fixture':'source-only'})
        self.native = patch.object(m, 'Native', FakeNative); self.native.start(); self.addCleanup(self.native.stop)
        FakeNative.next_edge = EDGE
        self.physical = patch.object(m.n,'finance_reference_files',return_value=dict(directory={'fixture':'synthetic inode'},input={'fixture':'synthetic file'}))
        self.physical.start(); self.addCleanup(self.physical.stop)
    def arm(self): return m.transact(self.root, self.release, self.old, 'arm')
    def capture(self):
        self.old['financeOwnershipCustody'] = self.arm().record
        return m.transact(self.root, self.release, self.old, 'capture')
    def test_exact_edge(self): self.assertEqual(m.edge(EDGE), EDGE)
    def test_invalid_edges(self):
        cases = [None, {}, dict(EDGE, approval=True), dict(EDGE, clientId='foreign'), dict(EDGE, clientUuid=7),
                 dict(EDGE, serviceAccountSubject=uid(1)), dict(EDGE, serviceAccountSubject='manual-human-approval')]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError): m.edge(value)
    def test_unknown_root_origins_refused(self):
        for kind in ('logger-json', 'manual-ids', 'source-lease', 'export-file', 'podman-events', None):
            value = receipt(); value['original']['kind'] = kind
            with self.subTest(kind=kind), self.assertRaises(ValueError): m.original_receipt(value, SOURCE_PIN, ISSUER)
    def test_source_issuer_and_native_origin_changes_refused(self):
        for key,value in [('source',{}),('issuer','https://foreign.invalid'),('activationAuthorized',True),('intentSha256','bad')]:
            item=receipt(); item[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): m.original_receipt(item,SOURCE_PIN,ISSUER)
        for key,value in [('querySha256','f'*64),('rowSha256','f'*64),('source',{}),('kind','username-lookup')]:
            item=receipt(); item['original']['database'][key]=value
            with self.subTest(database=key),self.assertRaises(ValueError): m.original_receipt(item,SOURCE_PIN,ISSUER)
    def test_fresh_arm_is_custody_not_permission(self):
        result=self.arm(); self.assertIs(type(result),m.RootFinanceResult)
        self.assertEqual(result.field,'financeOwnershipCustody'); self.assertNotIn('nativeFinanceOwnership',result.record)
        self.assertIsNone(result.record['priorReceiptSha256'])
    def test_retained_arm_requires_original_receipt(self):
        self.old['nativeFinanceOwnershipReceipt']=receipt(); result=self.arm()
        self.assertEqual(result.record['priorReceiptSha256'],m.sha(m.encoded(receipt())))
    def test_manual_receipt_not_admitted(self):
        self.old['nativeFinanceOwnershipReceipt']={'nativeFinanceOwnership':EDGE}
        with self.assertRaises(ValueError): self.arm()
    def test_arm_replay_refuses(self):
        self.old['financeOwnershipCustody']=self.arm().record
        with self.assertRaises(ValueError): self.arm()
    def test_wrong_phase_action_refuse(self):
        for action in ('approve','restore','replay',''):
            with self.subTest(action=action),self.assertRaises(ValueError): m.transact(self.root,self.release,self.old,action)
        self.old['phase']='active'
        with self.assertRaises(ValueError): self.arm()
    def test_capture_requires_root_arm(self):
        with self.assertRaises(ValueError): m.transact(self.root,self.release,self.old,'capture')
    def test_fresh_native_capture(self):
        result=self.capture(); self.assertEqual(result.record['nativeFinanceOwnership'],EDGE)
        self.assertEqual(result.record['original'],ORIGINAL)
        self.assertTrue(result.backend.observed and result.backend.exported)
        self.assertFalse(result.record['activationAuthorized']); self.assertFalse(result.record['readinessAuthorized'])
    def test_retained_capture_preserves_original(self):
        self.old['nativeFinanceOwnershipReceipt']=receipt()
        result=self.capture(); self.assertEqual(result.record['original'],receipt()['original'])
    def test_retained_native_replacement_refuses(self):
        self.old['nativeFinanceOwnershipReceipt']=receipt(); FakeNative.next_edge=dict(EDGE,serviceAccountSubject=uid(9))
        with self.assertRaises(ValueError): self.capture()
    def test_arm_source_changed_refuses(self):
        self.old['financeOwnershipCustody']=self.arm().record
        self.old['financeOwnershipCustody']['source']['financeScriptSha256']='0'*64
        with self.assertRaises(ValueError): m.transact(self.root,self.release,self.old,'capture')
    def test_capture_replay_refuses(self):
        result=self.capture(); self.old['nativeFinanceOwnershipReceipt']=result.record
        with self.assertRaises(ValueError): m.transact(self.root,self.release,self.old,'capture')
    def test_changed_typed_result_refuses(self):
        result=self.arm(); result.record['source']={}
        with self.assertRaises(ValueError): result.recheck()
    def test_constructor_requires_process_local_issuer(self):
        with self.assertRaises(ValueError): m.RootFinanceResult(object(),FakeNative(self.root,self.release,self.old),'arm',{})
    def test_closed_result_refuses(self):
        result=self.arm(); result.close()
        with self.assertRaises(ValueError): result.recheck()
    def test_dual_cas_mismatch_prevents_dynamic_publication(self):
        result=self.arm(); value=dict(self.old,**{result.field:result.record})
        with patch.object(m.n,'lock_held'),patch.object(m.n,'read_file',side_effect=[m.encoded(value),b'{}']),patch.object(m,'publish_input') as out:
            with self.assertRaises(ValueError): result.publish(value)
            out.assert_not_called()
    def test_exact_cas_fresh_input_publication_and_single_use(self):
        result=self.arm(); value=dict(self.old,**{result.field:result.record}); raw=m.encoded(value)
        with patch.object(m.n,'lock_held'),patch.object(m.n,'read_file',return_value=raw),patch.object(m,'publish_input') as out:
            reference=result.publish(value); self.assertIs(type(reference),m.RootFinanceReference)
            self.assertEqual(reference.record['publisher']['origin'],'root-native-finance-ownership')
            reference.recheck(value)
            sent=out.call_args.args[0]
            self.assertEqual(sent['status'],'fresh'); self.assertIsNone(sent['nativeFinanceOwnership'])
            self.assertEqual(sent['intentSha256'],m.sha(raw))
            with self.assertRaises(ValueError): result.publish(value)
    def test_exact_cas_retained_input_only_from_native_receipt(self):
        self.old['nativeFinanceOwnershipReceipt']=receipt(); result=self.arm()
        value=dict(self.old,**{result.field:result.record}); raw=m.encoded(value)
        with patch.object(m.n,'lock_held'),patch.object(m.n,'read_file',return_value=raw),patch.object(m,'publish_input') as out:
            result.publish(value); self.assertEqual(out.call_args.args[0]['nativeFinanceOwnership'],EDGE)
    def test_capture_publishes_retained_input_for_next_plain_stop_start(self):
        result=self.capture(); value=dict(self.old,**{result.field:result.record}); raw=m.encoded(value)
        with patch.object(m.n,'lock_held'),patch.object(m.n,'read_file',return_value=raw),patch.object(m,'publish_input') as out:
            result.publish(value)
            self.assertEqual(out.call_args.args[0]['status'],'retained')
            self.assertEqual(out.call_args.args[0]['nativeFinanceOwnership'],EDGE)
    def test_module_gates_unchanged_and_exact_source_pin(self):
        source=ROOT.parent/'module-delivery/keycloak/stack.config/keycloak/configure-finance.sh'
        text=source.read_text(); start=text.index('  # Production receives a Root-owned'); end=text.index("  finance_uuid=",start)
        restored=(text[:start]+text[end:]).encode()
        self.assertEqual(m.sha(restored),'24820035b3d1e5d8b9d477c84a7929defd240db1a0391a3c70743108fbebefb9')
        self.assertEqual(m.sha(source.read_bytes()),m.FINANCE_SOURCE_SHA256)
    def test_no_autocreating_get_no_logger_origin(self):
        self.assertNotIn('service-account-user',m.SQL)
        self.assertIn('u.service_account_client_link=c.id',m.SQL)
        self.assertIn('BEGIN READ ONLY',m.SQL)
        self.assertNotIn('journalctl',SOURCE.read_text()); self.assertNotIn("'events'",SOURCE.read_text())


class OriginalExecutionSource(unittest.TestCase):
    def test_exact_loaded_original_execution_properties(self):
        backend=object.__new__(m.Native)
        backend.units={'keycloak-configure':types.SimpleNamespace(scope='rootful',name='webservices-keycloak-configure.service',role='oneshot')}
        backend.commands={'rootful':(['fixture-manager'],['fixture-store'])}
        props={key:'' for key in m.r.PROPERTIES}
        props.update(Id='webservices-keycloak-configure.service',LoadState='loaded',DropInPaths='',ConditionResult='yes',AssertResult='yes',Type='oneshot')
        def run(args,timeout): return types.SimpleNamespace(stdout='\n'.join(k+'='+v for k,v in props.items()))
        backend.selection=types.SimpleNamespace(run=run,left=lambda:120)
        self.assertEqual(backend.props('keycloak-configure'),props)
    def test_dropin_skipped_unloaded_or_wrong_type_cannot_mint_origin(self):
        backend=object.__new__(m.Native)
        backend.units={'keycloak-configure':types.SimpleNamespace(scope='rootful',name='webservices-keycloak-configure.service',role='oneshot')}
        backend.commands={'rootful':(['fixture-manager'],['fixture-store'])}
        base={key:'' for key in m.r.PROPERTIES}
        base.update(Id='webservices-keycloak-configure.service',LoadState='loaded',DropInPaths='',ConditionResult='yes',AssertResult='yes',Type='oneshot')
        for key,value in [('DropInPaths','/foreign/override.conf'),('ConditionResult','no'),('AssertResult','no'),('LoadState','masked'),('Type','simple')]:
            props=dict(base,**{key:value})
            backend.selection=types.SimpleNamespace(run=lambda args,timeout:types.SimpleNamespace(stdout='\n'.join(k+'='+v for k,v in props.items())),left=lambda:120)
            with self.subTest(key=key),self.assertRaises(ValueError): backend.props('keycloak-configure')


class OriginalLiveCollector(unittest.TestCase):
    def setUp(self):
        # Exercise ACTUAL production observer with scalar native fixtures only.
        self.b=object.__new__(m.Native); self.b.boot=uid(3)
        self.b.selection=types.SimpleNamespace(left=lambda:120)
        self.custody=dict(bootId=uid(3),previousInvocationId='',startMonotonicUSec=1)
        self.running=dict(InvocationID='1'*32,ExecMainStartTimestampMonotonic='2',ActiveState='activating',SubState='start',NRestarts='0')
        self.done=dict(self.running,ActiveState='active',SubState='exited',Result='success',ExecMainCode='1',ExecMainStatus='0',ExecMainExitTimestampMonotonic='3')
        self.live=copy.deepcopy(ORIGINAL['container'])
    def observe(self, rows):
        with patch.object(self.b,'props',side_effect=rows),patch.object(self.b,'live',return_value=self.live),patch.object(m.time,'sleep'):
            return self.b.observe_original(self.custody)
    def test_original_live_success(self):
        result=self.observe([self.running,self.done]); self.assertEqual(result['container'],self.live)
    def test_missed_original_refuses_not_reconstructed(self):
        with self.assertRaises(ValueError): self.observe([self.done])
    def test_replayed_invocation_refuses(self):
        with self.assertRaises(ValueError): self.observe([self.running,dict(self.done,InvocationID='2'*32)])
    def test_original_failure_refuses(self):
        with self.assertRaises(ValueError): self.observe([self.running,dict(self.done,ExecMainStatus='1')])
    def test_original_restart_refuses(self):
        with self.assertRaises(ValueError): self.observe([self.running,dict(self.done,NRestarts='1')])
    def test_original_container_replacement_refuses(self):
        with patch.object(self.b,'props',side_effect=[self.running,self.running]),patch.object(self.b,'live',side_effect=[self.live,dict(self.live,id='f'*64)]),patch.object(m.time,'sleep'):
            with self.assertRaises(ValueError): self.b.observe_original(self.custody)


class NativeExportProjection(unittest.TestCase):
    def setUp(self):
        self.b=object.__new__(m.Native); self.b.source=copy.deepcopy(SOURCE_PIN)
        self.calls=[]; self.response=json.dumps([EDGE])
        def run(args,timeout):
            self.calls.append(args); return types.SimpleNamespace(stdout=self.response)
        self.b.selection=types.SimpleNamespace(left=lambda:120,run=run)
        self.b.commands={'rootful':(['systemctl'],['podman','--root','/fixture/EXACT-store'])}
        self.b.units={'postgres':types.SimpleNamespace(scope='rootful')}
        self.props=dict(ActiveState='active',Result='success',InvocationID='2'*32)
        self.live=dict(id='9'*64,image='sha256:'+'d'*64,source=SOURCE_PIN['postgres'],conmon={'cgroup':'fixture'})
    def export(self):
        with patch.object(self.b,'props',return_value=self.props),patch.object(self.b,'live',return_value=self.live):
            return self.b.export_edge()
    def test_exact_selected_native_fk_readonly_export(self):
        native,origin=self.export(); self.assertEqual(native,EDGE)
        command=self.calls[0]
        self.assertEqual(command[:6],['podman','--root','/fixture/EXACT-store','exec','--','9'*64])
        self.assertEqual(command[-1],m.SQL); self.assertEqual(origin['querySha256'],m.sha(m.SQL.encode()))
        self.assertNotIn('service-account-user',' '.join(command)); self.assertNotIn('password',' '.join(command).lower())
    def test_native_missing_or_ambiguous_link_refuses(self):
        for rows in ([],[EDGE,EDGE],[dict(EDGE,clientId='foreign')]):
            self.response=json.dumps(rows)
            with self.subTest(rows=rows),self.assertRaises(ValueError): self.export()
    def test_changed_native_export_origin_refuses(self):
        changed=dict(self.props,InvocationID='3'*32)
        with patch.object(self.b,'props',side_effect=[self.props,self.props,changed]),patch.object(self.b,'live',return_value=self.live):
            with self.assertRaises(ValueError): self.b.export_edge()
    def test_native_daemon_not_running_refuses_before_query(self):
        self.props['ActiveState']='inactive'
        with self.assertRaises(ValueError): self.export()
        self.assertEqual(self.calls,[])


class DynamicReadonlySlot(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'dynamic'; self.path.mkdir()
        self.input=dict(schemaVersion=1,kind='root-native-finance-input',root='/fixture/root',release='/fixture/root/releases/one',
                        intentSha256='f'*64,sourceSha256=m.FINANCE_SOURCE_SHA256,issuer=ISSUER,status='fresh',nativeFinanceOwnership=None)
    def publish(self):
        with patch.object(m,'SLOT',self.path),patch.object(m,'slot_directory',side_effect=lambda descriptor=None:os.open(self.path,os.O_DIRECTORY)),\
             patch.object(m.os,'fchown') as ownership,patch.object(m.n,'read_file',side_effect=lambda p:p.read_bytes()):
            m.publish_input(self.input)
            ownership.assert_called_once(); self.assertEqual(ownership.call_args.args[1:],(0,0))
    def test_next_retained_reference_without_sealed_inode_mutation(self):
        immutable=Path(self.temp.name)/'sealed.env'; immutable.write_bytes(b'FIXTURE=not-a-real-secret\n')
        before=(immutable.stat().st_ino,immutable.read_bytes()); directory=self.path.stat().st_ino
        self.publish(); first=(self.path/'input.json').stat().st_ino
        self.input.update(status='retained',nativeFinanceOwnership=EDGE); self.publish()
        self.assertNotEqual((self.path/'input.json').stat().st_ino,first)
        self.assertEqual(self.path.stat().st_ino,directory)
        self.assertEqual((immutable.stat().st_ino,immutable.read_bytes()),before)
        self.assertEqual((self.path/'input.json').stat().st_mode&0o777,0o444)
        self.assertEqual(json.loads((self.path/'input.json').read_text())['nativeFinanceOwnership'],EDGE)
    def test_foreign_root_slot_refuses_without_overwrite(self):
        self.publish(); original=(self.path/'input.json').read_bytes(); self.input['root']='/foreign'
        with self.assertRaises(ValueError): self.publish()
        self.assertEqual((self.path/'input.json').read_bytes(),original)
    def test_unclaimed_dynamic_content_refuses(self):
        (self.path/'authored').write_text('preserve')
        with self.assertRaises(ValueError): self.publish()
        self.assertEqual((self.path/'authored').read_text(),'preserve')


if __name__=='__main__': unittest.main(verbosity=2)
