#!/usr/bin/env python3
"""Hostile source fixtures for a proposed, never-installed private Caddy relay."""
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('private_ingress',ROOT/'runtime-generator/podman-ops/render-existing-host-ingress.py')
ingress=importlib.util.module_from_spec(spec);spec.loader.exec_module(ingress)
fence_spec=importlib.util.spec_from_file_location('guest_fence',ROOT/'runtime-generator/podman-ops/render-existing-host-guest-fence.py')
fence=importlib.util.module_from_spec(fence_spec);fence_spec.loader.exec_module(fence)
mail_spec=importlib.util.spec_from_file_location('private_mail',ROOT/'runtime-generator/podman-ops/render-existing-host-mail-ingress.py')
mail=importlib.util.module_from_spec(mail_spec);mail_spec.loader.exec_module(mail)


class PrivateIngressTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        for rel in ('site/global.settings','runtime/configs/caddy','quadlet/rootful'):
            (self.root/rel).mkdir(parents=True)
        self.guest={'name':'p0-venue-r1-agents','network':'p0-venue-r1',
            'networkConfig':{'address':'192.168.140.115/24','gateway':'192.168.140.1','nameservers':['192.168.140.1']},
            'servicePorts':{'https':56042,'imap':56047,'smtp':56044},
            'diskRoot':'/mnt/lab_debian/agent_vm/p0-venue-r1-agents','controlCommit':'a'*40}
        self.selector={'guest':self.guest,'rootful':{'stateRoot':'/var/lib/p0test-r1'},
                       'unitPrefix':'p0test-r1','ports':{'80':56045,'443':56042,'993':56047,'587':56044,'25':56032,'465':56043,
                                                       '7880':56048,'7881':56049,'7882':56050}}
        self.vm={key:self.guest[key] for key in ('name','network','networkConfig','servicePorts','diskRoot')}
        self.vm['runtime']={'controlCommit':'a'*40}
        self.domains={'venue':{'unitPrefix':'p0test-r1','portMap':self.selector['ports']}}
        names={'keycloak','matrix','mail','control','ntfy','portal','search'} | {'service'+str(i) for i in range(36)}
        (self.root/'runtime/configs/caddy/Caddyfile').write_text('\n'.join(n+'.{$DOMAIN} {' for n in sorted(names)))
        (self.root/'site/global.settings/stack.config.yaml').write_text('runtime:\n  domain: "datamancy.net"\n')
        self.quadlet=self.root/'quadlet/rootful/p0test-r1-caddy.container'
        self.good_quadlet=('[Container]\nContainerName=p0test-r1-caddy\nNetwork=host\n'
            'Environment=CONTAINERS_STORAGE_CONF=/var/lib/p0test-r1/containers-storage.conf\n'
            'Environment=CONTAINERS_CONF=/var/lib/p0test-r1/containers.conf\n')
        self.quadlet.write_text(self.good_quadlet)
        self.mail_quadlet=self.root/'quadlet/rootful/p0test-r1-mailserver.container'
        self.good_mail=('[Container]\nContainerName=p0test-r1-mailserver\n'
          'PublishPort=127.0.0.1:56032:25\nPublishPort=127.0.0.1:56043:465\n'
          'PublishPort=127.0.0.1:56044:587\nPublishPort=127.0.0.1:56047:993\n')
        self.mail_quadlet.write_text(self.good_mail)
        livekit_dir=self.root/'quadlet/rootless-apps';livekit_dir.mkdir()
        self.livekit_quadlet=livekit_dir/'p0test-r1-livekit.container'
        self.good_livekit=('[Container]\nContainerName=p0test-r1-livekit\nNetwork=p0test-r1-caddy.network\n'
            'PublishPort=127.0.0.1:56048:7880\n'
            'PublishPort=192.168.140.1:56049:56049/tcp\n'
            'PublishPort=192.168.140.1:56050:56050/udp\n')
        self.livekit_quadlet.write_text(self.good_livekit)
        self.save()

    def save(self):
        (self.root/'site/agent-vm.json').write_text(json.dumps(self.vm))
        (self.root/'podman-domains.json').write_text(json.dumps(self.domains))

    def test_only_guest_facing_caddy_transport_is_rendered_not_installed(self):
        result=ingress.render(self.root,self.selector)
        self.assertEqual(result['guestPorts'],[443,56042])
        self.assertIn('ListenStream=192.168.140.1:443\n',result['socket'])
        self.assertIn('ListenStream=192.168.140.1:56042\n',result['socket'])
        self.assertEqual(result['socket'].count('ListenStream='),2)
        self.assertIn('BindToDevice=virbr140',result['socket'])
        self.assertIn('BindsTo=p0test-r1-caddy.service',result['socket'])
        self.assertIn('WantedBy=p0test-r1.target',result['socket'])
        self.assertNotIn('WantedBy=sockets.target',result['socket'])
        self.assertIn('127.0.0.1:56042',result['service'])
        self.assertEqual(result['guestHttpPorts'],[80,56045])
        self.assertEqual(result['httpUpstream'],'127.0.0.1:56045')
        self.assertIn('ListenStream=192.168.140.1:80',result['httpSocket'])
        self.assertIn('WantedBy=p0test-r1.target',result['httpSocket'])
        self.assertNotIn('56001',result['socket']+result['service'])
        self.assertFalse(result['networkDefined'] or result['unitInstalled'] or result['activationAuthorized'])

    def test_proposed_firewall_denies_non_guest_and_unapproved_host_access(self):
        proposal=fence.render(self.root,self.selector)
        policy=proposal['nftables']
        self.assertFalse(proposal['applied'] or proposal['activationAuthorized'] or proposal['otherHostTablesModified'])
        self.assertEqual(proposal['caddyPorts'],[80,56045,443,56042])
        self.assertIn('iifname "virbr140" ip daddr != 192.168.140.1 drop',policy)
        self.assertIn('iifname != "virbr140" iifname != "lo" ip daddr 192.168.140.1 tcp dport { 53, 80, 443, 587, 993, 56045, 56042, 56044, 56047, 56049 } drop',policy)
        self.assertIn('iifname "virbr140" meta l4proto != { tcp, udp, icmp } drop',policy)
        self.assertIn('iifname != "virbr140" iifname != "lo" ip daddr 192.168.140.1 udp dport { 53, 56050 } drop',policy)
        self.assertIn('iifname "virbr140" ip daddr 192.168.140.1 tcp dport != { 22, 53, 80, 443, 587, 993, 56045, 56042, 56044, 56047, 56049 } drop',policy)
        self.assertIn('iifname "virbr140" ip daddr 192.168.140.1 udp dport != { 53, 67, 56050 } drop',policy)
        self.assertIn('iifname "virbr140" ip daddr 192.168.0.0/16 drop',policy)
        self.assertIn('iifname "virbr140" meta nfproto ipv6 drop',policy)
        self.assertNotIn('flush ruleset',policy)
        for hostile in ('wildcard','old-ports','hostnet','missing'):
            self.livekit_quadlet.write_text(self.good_livekit)
            if hostile=='wildcard':self.livekit_quadlet.write_text(self.good_livekit.replace('192.168.140.1:56049','0.0.0.0:56049'))
            elif hostile=='old-ports':self.livekit_quadlet.write_text(self.good_livekit.replace('56050:56050','56050:7882'))
            elif hostile=='hostnet':self.livekit_quadlet.write_text(self.good_livekit+'Network=host\n')
            else:self.livekit_quadlet.unlink()
            with self.subTest(hostile=hostile),self.assertRaises((fence.ingress.Refusal,fence.ingress.network.Refusal,fence.mail.ingress.Refusal,fence.mail.ingress.network.Refusal)):
                fence.render(self.root,self.selector)
        self.livekit_quadlet.write_text(self.good_livekit)
        if os.geteuid()==0 and shutil.which('nft'):
            source=self.root/'proposed-fence.nft';source.write_text(policy)
            parsed=subprocess.run(['nft','-c','-f',str(source)],capture_output=True,text=True,timeout=10)
            self.assertEqual(parsed.returncode,0,parsed.stderr)
        self.selector['guest']['networkConfig']['gateway']='192.168.0.1'
        with self.assertRaises((fence.ingress.Refusal,fence.ingress.network.Refusal)):
            fence.render(self.root,self.selector)

    def test_mail_only_tls_smtp_imap_guest_relay_and_hostile_publishers(self):
        result=mail.render(self.root,self.selector)
        self.assertFalse(result['activationAuthorized'] or result['unitInstalled'] or result['mailTlsProved'] or result['mailSinkProved'])
        self.assertEqual(len(result['units']),2)
        for name,expected_port in (('smtp',56044),('imap',56047)):
            item=next(row for row in result['units'] if row['unit'].endswith(name))
            self.assertEqual(item['upstream'],f'127.0.0.1:{expected_port}')
            self.assertIn('BindToDevice=virbr140',item['socket'])
            self.assertIn('WantedBy=p0test-r1.target',item['socket'])
            self.assertEqual(item['socket'].count('ListenStream='),2)
        for bad in ('wildcard','extra','hostnet','wrong-port','missing'):
            self.mail_quadlet.write_text(self.good_mail)
            selector=json.loads(json.dumps(self.selector))
            if bad=='wildcard':self.mail_quadlet.write_text(self.good_mail.replace('127.0.0.1:56044:587','56044:587'))
            elif bad=='extra':self.mail_quadlet.write_text(self.good_mail+'PublishPort=192.168.140.1:56034:80\n')
            elif bad=='hostnet':self.mail_quadlet.write_text(self.good_mail+'Network=host\n')
            elif bad=='wrong-port':selector['guest']['servicePorts']['imap']=56046
            else:self.mail_quadlet.unlink()
            with self.subTest(bad=bad),self.assertRaises((mail.ingress.Refusal,mail.ingress.network.Refusal)):
                mail.render(self.root,selector)

    def test_proposed_units_parse_offline_without_host_install(self):
        result=ingress.render(self.root,self.selector)
        units=self.root/'units';units.mkdir()
        socket=units/(result['unit']+'.socket');socket.write_text(result['socket'])
        service=units/(result['unit']+'.service');service.write_text(result['service'])
        http_socket=units/(result['httpUnit']+'.socket');http_socket.write_text(result['httpSocket'])
        http_service=units/(result['httpUnit']+'.service');http_service.write_text(result['httpService'])
        # Only synthetic dependency stubs for offline parser verification.
        caddy=units/'p0test-r1-caddy.service'
        caddy.write_text('[Unit]\nDescription=fixture only\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\n')
        target=units/'p0test-r1.target';target.write_text('[Unit]\nDescription=fixture only\n')
        mail_service=units/'p0test-r1-mailserver.service'
        mail_service.write_text('[Unit]\nDescription=fixture only\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\n')
        mail_units=[]
        for item in mail.render(self.root,self.selector)['units']:
            for suffix in ('socket','service'):
                path=units/(item['unit']+'.'+suffix);path.write_text(item[suffix]);mail_units.append(path)
        checked=subprocess.run(['systemd-analyze','verify',str(socket),str(service),str(http_socket),str(http_service),str(caddy),str(target),str(mail_service),*(str(p) for p in mail_units)],
                               capture_output=True,text=True,timeout=15)
        self.assertEqual(checked.returncode,0,checked.stderr)

    def test_bypassing_caddy_or_mixed_guest_or_tls_authority_refuses(self):
        for error in ('port','unit','network','caddy-net','caddy-publish','storage','acme'):
            self.quadlet.write_text(self.good_quadlet)
            self.domains['venue']['portMap']=self.selector['ports']
            (self.root/'site/global.settings/stack.config.yaml').write_text('runtime:\n  domain: "datamancy.net"\n')
            selector=json.loads(json.dumps(self.selector))
            if error=='port':self.domains['venue']['portMap']={'443':443,'993':56047,'587':56044}
            elif error=='unit':selector['unitPrefix']='webservices'
            elif error=='network':selector['guest']['networkConfig']['gateway']='192.168.122.1'
            elif error=='caddy-net':self.quadlet.write_text(self.good_quadlet.replace('Network=host','Network=p0test-r1-caddy.network'))
            elif error=='caddy-publish':self.quadlet.write_text(self.good_quadlet+'PublishPort=192.168.140.1:56001:8080\n')
            elif error=='storage':self.quadlet.write_text(self.good_quadlet.replace('/var/lib/p0test-r1/','/var/lib/webservices/'))
            elif error=='acme':(self.root/'site/global.settings/stack.config.yaml').write_text('runtime:\n  domain: "datamancy.net"\n  caddy_tls_mode: acme\n')
            self.save()
            with self.subTest(error=error),self.assertRaises((ingress.Refusal,ingress.network.Refusal)):
                ingress.render(self.root,selector)


if __name__=='__main__':unittest.main()
