import contextlib
import copy
import io
import ipaddress
import json
from pathlib import Path
import tempfile
import unittest

from p0core.cli import main
from p0core.model import ContractError
from p0core.netplan import plan_new, snapshot_from_ip_json


def snapshot():
    return {'schemaVersion': 1, 'interfaces': [{'name': 'lo', 'prefixes': ['127.0.0.1/8']}],
            'routes': ['0.0.0.0/0'], 'reservedPrefixes': []}


class NetworkPlanTests(unittest.TestCase):
    def test_observed_and_inactive_allocations_are_excluded(self):
        value = snapshot()
        value['interfaces'].append({'name': 'existing0', 'prefixes': ['172.16.0.1/24']})
        value['routes'].append('172.16.1.0/24')
        value['reservedPrefixes'].append('172.16.2.0/24')
        result = plan_new(value)
        self.assertEqual(result['desired']['subnet'], '172.16.3.0/24')
        self.assertEqual(result['desired']['gateway'], '172.16.3.1')
        self.assertEqual(result['desired']['ingressAddress'], '172.16.3.2')
        self.assertFalse(result['installationCertified'])
        self.assertTrue(result['nativeRecheckRequired'])

    def test_aggregate_allocations_and_pool_exhaustion_are_bounded(self):
        value = snapshot()
        value['reservedPrefixes'] = ['172.16.0.0/12', '10.0.0.0/8', '192.168.0.0/25']
        self.assertEqual(plan_new(value)['desired']['subnet'], '192.168.1.0/24')
        value['reservedPrefixes'].append('192.168.0.0/16')
        with self.assertRaises(ContractError):
            plan_new(value)
        value['reservedPrefixes'] = ['0.0.0.0/0']
        with self.assertRaises(ContractError):
            plan_new(value)

    def test_overlaps_merge_and_host_route_rounds_to_next_whole_subnet(self):
        value = snapshot()
        value['routes'] += ['172.16.0.128/25', '172.16.0.42/32', '172.16.0.0/25', '172.16.1.255/32']
        result = plan_new(value)
        self.assertEqual(result['desired']['subnet'], '172.16.2.0/24')
        chosen = ipaddress.ip_network(result['desired']['subnet'])
        for occupied in value['routes'][1:]:
            self.assertFalse(chosen.overlaps(ipaddress.ip_network(occupied)))

    def test_foreign_interface_is_not_adopted(self):
        value = snapshot()
        value['interfaces'].append({'name': 'p0v2edge0', 'prefixes': []})
        with self.assertRaises(ContractError):
            plan_new(value)
        for interface in ('eth0', 'p0v2toolonginterfacename', 'p0v2bad\nname'):
            with self.subTest(interface=interface), self.assertRaises(ContractError):
                plan_new(snapshot(), interface=interface)

    def test_hash_binds_exact_inventory_but_not_desired_when_unrelated(self):
        one, two = snapshot(), snapshot()
        two['routes'].append('203.0.113.0/24')
        self.assertEqual(plan_new(one)['desiredSha256'], plan_new(two)['desiredSha256'])
        self.assertNotEqual(plan_new(one)['inventorySha256'], plan_new(two)['inventorySha256'])
        self.assertEqual(plan_new(one), plan_new(copy.deepcopy(one)))

    def test_closed_schema_and_inventory_bounds(self):
        changes = ({'schemaVersion': True}, {'unknown': True}, {'routes': ['not-a-prefix']},
                   {'routes': ['fe80::%eth0/64']}, {'interfaces': [{'name': 'bad name', 'prefixes': []}]},
                   {'reservedPrefixes': ['10.0.0.0/8'] * 4097}, {'routes': False})
        for change in changes:
            with self.subTest(change=str(change)[:80]), self.assertRaises(ContractError):
                plan_new(snapshot() | change)

    def test_native_metadata_normalization_includes_every_supplied_table(self):
        addresses = [{'ifname': 'eth0', 'addr_info': [
            {'family': 'inet', 'local': '172.16.0.15', 'prefixlen': 24},
            {'family': 'inet6', 'local': '2001:db8::1', 'prefixlen': 64}]}]
        routes = [{'dst': 'default', 'gateway': '172.16.0.1'}, {'dst': '172.16.1.0/24', 'table': 100},
                  {'dst': '172.16.2.0/24', 'type': 'blackhole'}, {'dst': '203.0.113.1', 'table': 'local'}]
        value = snapshot_from_ip_json(addresses, routes, ['172.16.3.0/24'])
        self.assertEqual(plan_new(value)['desired']['subnet'], '172.16.4.0/24')
        self.assertIn('203.0.113.1/32', value['routes'])
        with self.assertRaises(ContractError):
            snapshot_from_ip_json(addresses, [{}])
        addresses[0]['addr_info'][0]['family'] = 'inet6'
        with self.assertRaises(ContractError):
            snapshot_from_ip_json(addresses, routes)

    def test_cli_is_pure_explicit_file_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'snapshot.json'
            path.write_text(json.dumps(snapshot()))
            with contextlib.redirect_stdout(io.StringIO()) as output:
                status = main(['network-plan', '--snapshot', str(path), '--network', 'edge', '--interface', 'p0v2edge0'])
            self.assertEqual(status, 0)
            frame = json.loads(output.getvalue())
            self.assertEqual(frame['desired']['networkName'], 'p0-edge')
            self.assertEqual(frame['scope'], 'new-network-plan-only')
