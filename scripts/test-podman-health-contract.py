#!/usr/bin/env python3
"""Source/native-parser contracts; no container, account, service or app start."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('health_contract',Path(__file__).with_name('test-podman-health.py'))
health=importlib.util.module_from_spec(spec);spec.loader.exec_module(health)

class HealthBarrierContract(unittest.TestCase):
    def setUp(self):
        self.services={'caddy':{'lifecycle':'daemon'},'configure':{'lifecycle':'oneshot'},
            'gateway':{'lifecycle':'daemon','dependencies':{'caddy':'healthy'}},
            'finance':{'lifecycle':'daemon','dependencies':{'configure':'completed'}}}
        self.owners={'caddy':None,'configure':'p-platform','gateway':'p-platform','finance':'p-finance'}
        self.batches=[({'name':'p-platform'},[],{(None,'p-caddy.service')}),
            (None,[],set()),({'name':'p-finance'},[],{('p-platform','p-configure.service')})]
    def check(self,early={'caddy'}):
        return health.check_activation_edges(self.services,self.owners,self.batches,early,'p')
    def test_early_root_and_completed_edges_keep_both_native_barriers(self):
        self.assertEqual(self.check(),2)
    def test_early_root_does_not_remove_native_observation_requirement(self):
        self.batches[0][2].clear()
        with self.assertRaises(AssertionError):self.check()
    def test_root_manager_order_is_required_without_explicit_bootstrap(self):
        with self.assertRaises(AssertionError):self.check(set())
    def test_nonroot_producer_cannot_use_root_bootstrap_exemption(self):
        self.batches=[self.batches[2],self.batches[0],self.batches[1]]
        with self.assertRaises(AssertionError):self.check({'caddy','configure'})
    def test_completed_edge_requires_native_barrier_not_manager_order_alone(self):
        self.batches[2][2].clear()
        with self.assertRaises(AssertionError):self.check()
    def test_unmanaged_and_managed_on_demand_are_not_automatic_consumers(self):
        for managed in (False,True):
            self.services['optional']={'lifecycle':'on-demand','quadletManaged':managed,
                'dependencies':{'absent':'healthy'}}
            self.assertEqual(self.check(),2)
    def test_native_regular_nonempty_marker_assertion_is_supported_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);marker=root/'marker';marker.write_text('source-only-ready\n')
            empty=root/'empty';empty.touch()
            # Native metadata predicates, NOT unit execution or target operations.
            for path,good in [(marker,True),(empty,False),(root,False),(root/'missing',False)]:
                value=subprocess.run(['systemd-analyze','condition','ConditionFileNotEmpty='+str(path)],
                    capture_output=True,timeout=10)
                self.assertEqual(value.returncode==0,good)
            unit=root/'source-marker.service';unit.write_text('[Unit]\nAssertFileNotEmpty='+str(marker)+
                '\n[Service]\nType=oneshot\nExecStart=/bin/true\n')
            value=subprocess.run(['systemd-analyze','verify','--man=no',str(unit)],capture_output=True,timeout=10)
            self.assertEqual(value.returncode,0)
            self.assertNotIn(b'Unknown key',value.stderr)

if __name__=='__main__':unittest.main()
