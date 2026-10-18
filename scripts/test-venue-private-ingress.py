#!/usr/bin/env python3
"""Synthetic root-owned relay lifecycle fixtures; no host network/unit mutation."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import shutil
import ssl
import subprocess
import struct
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

src=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-private-ingress.py'
spec=importlib.util.spec_from_file_location('private_ingress_fixture',src)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

@unittest.skipUnless(os.geteuid()==0,'protected synthetic journal fixture')
class PrivateIngress(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        self.b=self.root/'bundle';(self.b/'quadlet/rootful').mkdir(parents=True)
        (self.b/'quadlet/rootful/p0test-r1-caddy.container').write_text('DNS=192.168.140.1\n')
        self.unitdir=self.root/'units';self.unitdir.mkdir();self.p=self.root/'ledger.json';self.selector=self.root/'selector.json'
        self.plan={'prefix':'p0test-r1'};self.data={'plan':self.plan,'venueInstallerVersion':1,'venueInstallerPhase':'preparing','status':'units-staged','activationAuthorized':False}
        self.save();self.selector.write_text('{}')
        proposal={'unit':'p0test-r1-ingress-https','httpUnit':'p0test-r1-ingress-http','guestGateway':'192.168.140.1','bridge':'virbr140',
                  'socket':'https socket','service':'https service','httpSocket':'http socket','httpService':'http service'}
        mails={'units':[{'unit':'p0test-r1-ingress-'+name,'socket':name+' socket','service':name+' service'} for name in ('smtp','imap')]}
        for target,name,value in [(m,'UNIT_DIRECTORY',self.unitdir),(m.stage,'owned_plan',Mock(return_value=self.plan)),
                (m.https.network,'strict_json',Mock(return_value={})),(m.https,'render',Mock(return_value=proposal)),
                (m.mail,'render',Mock(return_value=mails))]:
            active=patch.object(target,name,value);active.start();self.addCleanup(active.stop)
        self.commands=[]
        def native(command,**kwargs):
            self.commands.append(command)
            if 'show' in command:return SimpleNamespace(returncode=0,stdout=('ActiveState=inactive\nUnitFileState=disabled\n\n'*8))
            return SimpleNamespace(returncode=0,stdout='')
        active=patch.object(m.graph,'run',side_effect=native);active.start();self.addCleanup(active.stop)
        self.controller=Mock();self.controller.digest='a'*64;self.controller.require_runtime.return_value={'phase':'starting','bootId':'fixture-boot'}
    def save(self):self.p.write_text(json.dumps(self.data));self.p.chmod(0o600)
    def ready(self):m.prepare(self.b,self.selector,self.p);self.data=json.loads(self.p.read_text())
    def starting(self):
        self.ready();self.data.update(venueInstallerVersion=2,venueInstallerPhase='starting',status='installed-starting',
            venueStartPhase='starting',activationAuthorized=True,venueStartHostContextSha256=self.controller.digest,venueStartMonotonicUsec=100);self.save()
    def test_prepare_records_eight_inactive_files_without_start_or_enable(self):
        self.ready();self.assertEqual(len(m.checked(self.b,self.selector,self.p)),8)
        self.assertEqual(self.commands,[['systemctl','daemon-reload']])
        self.assertEqual(self.data['venueIngressPhase'],'inert-ready')
        for p in self.unitdir.iterdir():self.assertEqual(p.stat().st_mode&0o777,0o644)
    def test_any_foreign_destination_refuses_before_first_write(self):
        foreign=self.unitdir/'p0test-r1-ingress-imap.service';foreign.write_text('authored')
        with self.assertRaises(m.Refusal):m.prepare(self.b,self.selector,self.p)
        self.assertEqual(list(self.unitdir.iterdir()),[foreign]);self.assertEqual(foreign.read_text(),'authored');self.assertEqual(self.commands,[])
    def test_public_dns_fallback_refuses_before_unit_install(self):
        (self.b/'quadlet/rootful/p0test-r1-caddy.container').write_text('DNS=192.168.140.1\nDNS=1.1.1.1\n')
        with self.assertRaisesRegex(m.Refusal,'exclusive isolated DNS'):m.prepare(self.b,self.selector,self.p)
        self.assertEqual(list(self.unitdir.iterdir()),[])
    def test_changed_file_stops_retirement_before_any_unlink(self):
        self.ready();self.data['venueInstallerPhase']='retiring';self.save();files=list(self.unitdir.iterdir());files[-1].write_text('authored')
        with self.assertRaises(m.Refusal):m.retire(self.b,self.selector,self.p)
        self.assertEqual(len(list(self.unitdir.iterdir())),8)
    def test_same_content_inode_replacement_refuses(self):
        self.ready();p=next(self.unitdir.iterdir());temp=self.root/'replacement';temp.write_bytes(p.read_bytes());temp.chmod(0o644);temp.replace(p)
        with self.assertRaises(m.Refusal):m.checked(self.b,self.selector,self.p)
    def test_symlink_replacement_refuses(self):
        self.ready();p=next(self.unitdir.iterdir());target=self.root/'authored';target.write_text('private');p.unlink();p.symlink_to(target)
        with self.assertRaises(m.Refusal):m.checked(self.b,self.selector,self.p)
        self.assertEqual(target.read_text(),'private')
    def test_retire_requires_all_inactive_install_states_and_jobs(self):
        self.ready();self.data['venueInstallerPhase']='retiring';self.save()
        for result in [SimpleNamespace(returncode=1,stdout=''),SimpleNamespace(returncode=0,stdout='ActiveState=inactive\n'),
                SimpleNamespace(returncode=0,stdout='ActiveState=active\nUnitFileState=disabled\n'*8),
                SimpleNamespace(returncode=0,stdout='ActiveState=inactive\nUnitFileState=enabled\n'*8)]:
            with self.subTest(result=result),patch.object(m.graph,'run',return_value=result):
                with self.assertRaises(m.Refusal):m.retire(self.b,self.selector,self.p)
                self.assertEqual(len(list(self.unitdir.iterdir())),8)
    def test_retire_pending_or_malformed_job_refuses(self):
        self.ready();self.data['venueInstallerPhase']='retiring';self.save()
        show=SimpleNamespace(returncode=0,stdout='ActiveState=inactive\nUnitFileState=disabled\n'*8)
        for jobs in ('1 p0test-r1-ingress-https.socket start waiting','unreadable'):
            with self.subTest(jobs=jobs),patch.object(m.graph,'run',side_effect=[show,SimpleNamespace(returncode=0,stdout=jobs)]):
                with self.assertRaises(m.Refusal):m.retire(self.b,self.selector,self.p)
                self.assertEqual(len(list(self.unitdir.iterdir())),8)
    def test_exact_inactive_retirement_unlinks_only_receipted_files(self):
        self.ready();self.data['venueInstallerPhase']='retiring';self.save();foreign=self.unitdir/'other-owner.service';foreign.write_text('keep')
        m.retire(self.b,self.selector,self.p)
        self.assertEqual(list(self.unitdir.iterdir()),[foreign]);data=json.loads(self.p.read_text());self.assertEqual(len(data['venueIngressRetired']),8)
        self.assertEqual(data['venueIngressPhase'],'retired-inert');self.assertFalse(any('stop' in row or 'reset-failed' in row for row in self.commands))
    def fake_runtime(self,lease=contextlib.nullcontext):
        return patch.object(m,'load',side_effect=lambda name,file:SimpleNamespace(lifecycle=lambda context:lease()) if file=='venue-start-quarantine.py' else SimpleNamespace(checked=lambda *a:{}) if file=='venue-root-health.py' else SimpleNamespace(reserve=Mock()))
    def test_fenced_or_expired_queue_never_checks_network_or_starts(self):
        self.starting();self.data['activationAuthorized']=False;self.save();self.commands.clear()
        with self.fake_runtime(),patch.object(m,'native_network') as native:
            with self.assertRaises(m.Refusal):m.queue(self.b,self.selector,self.p,self.controller,time.monotonic()+10,['p0test-r1-caddy.service'])
            native.assert_not_called();self.assertEqual(self.commands,[])
    def test_foreign_unit_name_never_reaches_network_or_native_start(self):
        self.starting();self.commands.clear()
        with self.fake_runtime(),patch.object(m,'native_network') as native:
            with self.assertRaises(m.Refusal):m.queue(self.b,self.selector,self.p,self.controller,time.monotonic()+10,['original-production.service'])
            native.assert_not_called();self.assertEqual(self.commands,[])
    def test_native_network_failure_never_queues_a_unit(self):
        self.starting();self.commands.clear()
        with self.fake_runtime(),patch.object(m,'native_network',side_effect=m.Refusal('wrong native fence')):
            with self.assertRaises(m.Refusal):m.queue(self.b,self.selector,self.p,self.controller,time.monotonic()+10,['p0test-r1-caddy.service'])
            self.assertEqual(self.commands,[])
    def test_queue_intent_precedes_native_ack_inside_lease(self):
        self.starting();held=[]
        @contextlib.contextmanager
        def lease():
            held.append(True)
            try:yield
            finally:held.pop()
        def native(command,**kwargs):
            self.assertTrue(held);self.assertEqual(json.loads(self.p.read_text())['venueIngressStartPending'],['p0test-r1-caddy.service'])
            return SimpleNamespace(returncode=0)
        with self.fake_runtime(lease),patch.object(m,'native_network'),patch.object(m.graph,'run',side_effect=native):
            m.queue(self.b,self.selector,self.p,self.controller,time.monotonic()+10,['p0test-r1-caddy.service'])
        self.assertFalse(held);self.assertNotIn('venueIngressStartPending',json.loads(self.p.read_text()))
    def test_unknown_native_ack_retains_intent_and_never_replays(self):
        self.starting()
        with self.fake_runtime(),patch.object(m,'native_network'),patch.object(m.graph,'run',side_effect=TimeoutError('unknown ACK')) as native:
            with self.assertRaises(TimeoutError):m.queue(self.b,self.selector,self.p,self.controller,time.monotonic()+10,['p0test-r1-caddy.service'])
            native.assert_called_once();self.assertIn('venueIngressStartPending',json.loads(self.p.read_text()))
            with self.assertRaisesRegex(m.Refusal,'no replay'):m.queue(self.b,self.selector,self.p,self.controller,time.monotonic()+10,['p0test-r1-caddy.service'])
            native.assert_called_once()
    def test_wait_releases_lease_and_accepts_operator_fencing(self):
        self.starting();held=[]
        @contextlib.contextmanager
        def lease():
            held.append(True)
            try:yield
            finally:held.pop()
        def cancel(_):
            self.assertFalse(held);self.data=json.loads(self.p.read_text());self.data['activationAuthorized']=False;self.save()
        with self.fake_runtime(lease),patch.object(m.time,'sleep',side_effect=cancel):
            with self.assertRaises(m.Refusal):m.wait(self.b,self.selector,self.p,self.controller,time.monotonic()+10,lambda *args:None)
        self.assertFalse(held)
    def test_read_only_probe_does_not_hold_lease_and_late_fence_wins(self):
        self.starting();held=[]
        @contextlib.contextmanager
        def lease():
            held.append(True)
            try:yield
            finally:held.pop()
        def probe(*args):
            self.assertFalse(held);self.data=json.loads(self.p.read_text());self.data['activationAuthorized']=False;self.save();return True
        with self.fake_runtime(lease):
            with self.assertRaises(m.Refusal):m.wait(self.b,self.selector,self.p,self.controller,time.monotonic()+10,probe)
        self.assertFalse(held)
    def test_socket_readiness_requires_current_epoch_exact_fragment_and_no_overrides(self):
        self.starting();name='p0test-r1-ingress-https.socket'
        observed=m.load('fixture_socket_observer','venue-start-quarantine.py').observed_ready
        base={'ActiveState':'active','Result':'success','ExecMainStartTimestampMonotonic':'101',
              'InactiveExitTimestampMonotonic':'0','FragmentPath':str(self.unitdir/name),'DropInPaths':''}
        def native(row):return SimpleNamespace(returncode=0,stdout='\n'.join(k+'='+v for k,v in row.items()))
        with patch.object(m,'load',return_value=SimpleNamespace(observed_ready=observed)):
            with patch.object(m.graph,'run',return_value=native(base)):self.assertTrue(m.sockets_ready(self.data,[name]))
            with patch.object(m.graph,'run',return_value=native({**base,'ExecMainStartTimestampMonotonic':'99'})):self.assertFalse(m.sockets_ready(self.data,[name]))
            for values in [{'FragmentPath':'/foreign.service'},{'DropInPaths':'/foreign.override'}]:
                with self.subTest(values=values),patch.object(m.graph,'run',return_value=native({**base,**values})):
                    with self.assertRaises(m.Refusal):m.sockets_ready(self.data,[name])
    def test_bad_certificate_or_permissions_are_not_transient_success(self):
        self.starting()
        for error in [PermissionError('not readable'),ssl.SSLCertVerificationError('wrong scope root')]:
            with self.subTest(error=error),self.fake_runtime(),patch.object(m.time,'sleep') as sleep:
                def fail(*args):raise error
                with self.assertRaises(m.Refusal):m.wait(self.b,self.selector,self.p,self.controller,time.monotonic()+10,fail)
                sleep.assert_not_called()

@unittest.skipUnless(os.geteuid()==0 and shutil.which('openssl'),'root-owned synthetic public CA fixture')
class ScopedCa(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        self.b=self.root/'bundle';self.b.mkdir();self.ca=self.root/'ca';self.ca.mkdir();self.certs=self.root/'certs';self.certs.mkdir()
        self.cert=self.certs/'pki/authorities/local/root.crt';self.cert.parent.mkdir(parents=True)
        for name,target in [('Scoped',self.cert),('Other',self.root/'other.crt')]:
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN='+name,
                '-addext','basicConstraints=critical,CA:TRUE','-keyout',str(self.root/(name+'.key')),'-out',str(target)],
                check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (self.ca/'caddy-ca.crt').write_bytes((self.root/'other.crt').read_bytes()+self.cert.read_bytes())
        (self.b/'stack.ir.json').write_text(json.dumps({'volumes':{'caddy_ca':{'hostPath':str(self.ca)},'caddy_certs':{'hostPath':str(self.certs)}}}))
        self.data={'venueDataBindDirs':[{'path':str(p),'dev':p.stat().st_dev,'ino':p.stat().st_ino} for p in (self.ca,self.certs)]}
    def test_only_this_scoped_root_is_trusted_not_the_full_public_bundle(self):
        trust,digest=m.ca_context(self.b,self.data,{})
        self.assertTrue(trust.check_hostname);self.assertEqual(trust.verify_mode,ssl.CERT_REQUIRED)
        self.assertEqual(len(trust.get_ca_certs()),1);self.assertEqual(trust.get_ca_certs()[0]['subject'][0][0][1],'Scoped')
        self.assertEqual(digest,hashlib.sha256((self.ca/'caddy-ca.crt').read_bytes()).hexdigest())
    def test_unpublished_ca_or_foreign_directory_never_becomes_ready(self):
        (self.ca/'caddy-ca.crt').write_bytes((self.root/'other.crt').read_bytes())
        with self.assertRaises(FileNotFoundError):m.ca_context(self.b,self.data,{})
        self.data['venueDataBindDirs'][0]['ino']+=1
        with self.assertRaises(m.Refusal):m.ca_context(self.b,self.data,{})

class PrivateDns(unittest.TestCase):
    def response(self,*,address='192.168.140.1',flags=0x8180,peer='192.168.140.1',truncated=False,nodata=False):
        stream=Mock();stream.__enter__=Mock(return_value=stream);stream.__exit__=Mock(return_value=False)
        def reply(_):
            packet=stream.sendto.call_args.args[0];nonce=struct.unpack('!H',packet[:2])[0]
            body=(struct.pack('!6H',nonce,flags,1,0 if nodata else 1,0,0)+packet[12:]+
                  (b'' if nodata else b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton(address)))
            return (body[:-1] if truncated else body),(peer,53)
        stream.recvfrom.side_effect=reply
        return patch.object(m.socket,'socket',return_value=stream)
    def test_exact_private_answer_without_host_resolver(self):
        with self.response(),patch.object(m.socket,'getaddrinfo') as host:
            self.assertEqual(m.dns_addresses('keycloak.example.invalid','192.168.140.1'),['192.168.140.1']);host.assert_not_called()
    def test_ipv6_requires_explicit_successful_nodata_not_any_answer_or_error(self):
        with self.response(nodata=True):self.assertEqual(m.dns_addresses('keycloak.example.invalid','192.168.140.1',ipv6=True),[])
        for kwargs in ({},{'nodata':True,'flags':0x8182}):
            with self.subTest(kwargs=kwargs),self.response(**kwargs),self.assertRaises(m.Refusal):m.dns_addresses('keycloak.example.invalid','192.168.140.1',ipv6=True)
    def test_foreign_address_peer_truncation_or_server_error_refuses(self):
        for kwargs in [{'address':'203.0.113.1'},{'peer':'1.1.1.1'},{'flags':0x8183},{'flags':0x8380},{'truncated':True}]:
            with self.subTest(kwargs=kwargs),self.response(**kwargs),self.assertRaises(m.Refusal):m.dns_addresses('keycloak.example.invalid','192.168.140.1')

if __name__=='__main__':unittest.main()
