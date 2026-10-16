#!/usr/bin/env python3
"""Hostile source fixtures: network XML is proposed only, never defined."""
import importlib.util
import ipaddress
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

source=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/render-existing-host-guest-network.py'
spec=importlib.util.spec_from_file_location('venue_network',source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class ProposedNetworkTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup)
        self.bundle=Path(self.folder.name)/'bundle'
        (self.bundle/'site/global.settings').mkdir(parents=True)
        (self.bundle/'runtime/configs/caddy').mkdir(parents=True)
        self.guest={'name':'p0-venue-r1-agents','network':'p0-venue-r1',
            'networkConfig':{'address':'192.168.140.115/24','gateway':'192.168.140.1',
                             'nameservers':['192.168.140.1']},
            'servicePorts':{'https':56042,'imap':56047,'smtp':56044},
            'diskRoot':'/mnt/lab_debian/agent_vm/p0-venue-r1-agents','controlCommit':'a'*40}
        self.selector={'guest':self.guest,'ports':{'443':56042,'993':56047,'587':56044}}
        self.vm={key:self.guest[key] for key in ('name','network','networkConfig','servicePorts','diskRoot')}
        self.vm['runtime']={'controlCommit':'a'*40}
        self.domains={'venue':{'portMap':self.selector['ports']}}
        self.caddy_labels={'keycloak','matrix','mail','control','ntfy','portal','search'} | {'service'+str(i) for i in range(36)}
        self.save()

    def save(self):
        (self.bundle/'site/agent-vm.json').write_text(json.dumps(self.vm))
        (self.bundle/'podman-domains.json').write_text(json.dumps(self.domains))
        (self.bundle/'site/global.settings/stack.config.yaml').write_text('runtime:\n  domain: "datamancy.net"\n')
        (self.bundle/'runtime/configs/caddy/Caddyfile').write_text('\n'.join(
            name+'.{$DOMAIN} {' for name in sorted(self.caddy_labels)))

    def test_exact_private_network_xml_and_no_mutating_operation(self):
        xml,info=module.render(self.bundle,self.selector)
        root=ET.fromstring(xml)
        self.assertEqual(root.findtext('name'),'p0-venue-r1')
        self.assertEqual(root.find('forward').get('mode'),'nat')
        self.assertEqual(root.find('bridge').get('name'),'virbr140')
        self.assertEqual(root.find('domain').get('localOnly'),'yes')
        names={row.text for row in root.findall('./dns/host/hostname')}
        self.assertEqual(len(names),len(self.caddy_labels)+1)
        self.assertIn('keycloak.datamancy.net',names)
        self.assertIn('datamancy.net',names)
        self.assertEqual(root.find('ip').get('address'),'192.168.140.1')
        self.assertEqual((info['defined'],info['activated'],info['ingressProven']),(False,False,False))
        self.assertFalse(any(item.tag=='dhcp' for item in root.iter()))

    def test_route_network_and_link_collisions_refuse(self):
        subnet=ipaddress.ip_network('192.168.140.0/24')
        for routes,names,links in (([{'dst':'192.168.140.64/26'}],[],[]),
                                   ([],['p0-venue-r1'],[]),
                                   ([],[],[{'ifname':'virbr140'}])):
            with self.subTest(routes=routes,names=names,links=links),self.assertRaises(module.Refusal):
                module.screen_host(subnet,'p0-venue-r1','virbr140',
                                   routes=routes,network_names=names,links=links)
        self.assertFalse(module.screen_host(subnet,'p0-venue-r1','virbr140',
                          routes=[{'dst':'default'},{'dst':'192.168.122.0/24'}],
                          network_names=['default','p0-clean-install-net'],links=[])['routeCollision'])

    def test_mixed_site_old_disks_ports_network_and_dns_refuse(self):
        for field,value in (('diskRoot','/mnt/lab_debian/agent_vm/clean-role'),
                            ('name','p0-agents'),('network','default')):
            guest=json.loads(json.dumps(self.guest));guest[field]=value
            with self.subTest(field=field),self.assertRaises(module.Refusal):
                module.render(self.bundle,{'guest':guest})
        self.vm['servicePorts']['https']=443;self.save()
        with self.assertRaises(module.Refusal):module.render(self.bundle,self.selector)
        self.vm['servicePorts']['https']=56042;self.vm['networkConfig']['nameservers']=['8.8.8.8'];self.save()
        with self.assertRaises(module.Refusal):module.render(self.bundle,self.selector)
        self.vm['networkConfig']['nameservers']=['192.168.140.1']
        self.caddy_labels.remove('keycloak');self.save()
        with self.assertRaises(module.Refusal):module.render(self.bundle,self.selector)

    def test_duplicate_authority_and_symlinked_config_refuse(self):
        path=self.bundle/'site/agent-vm.json'
        path.write_text('{"name":"p0-venue-r1-agents","name":"p0-agents"}')
        with self.assertRaises(module.Refusal):module.render(self.bundle,self.selector)
        path.unlink();path.symlink_to(self.bundle/'podman-domains.json')
        with self.assertRaises(module.Refusal):module.render(self.bundle,self.selector)


if __name__=='__main__':unittest.main()
