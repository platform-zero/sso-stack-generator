#!/usr/bin/env python3
"""Only an already fully retired, never-active composite can be adopted."""
import importlib.util
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import unittest

src=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-install-inert.py'
spec=importlib.util.spec_from_file_location('venue_installer_composite_adoption',src)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class AdoptCompletedComposite(unittest.TestCase):
    def setUp(self):
        self.bundle=Path('/private/bundle');self.ledger=Path('/private/ledger')
        self.plan={'accounts':[{'name':'isolated'}],'roots':{'rootful-state':'/nonexistent/venue-test-store'}}
        self.data={'plan':self.plan,'venueInstallerVersion':1,'venueInstallerPhase':'inert-ready',
                   'activationAuthorized':False,'venueReleasePhase':'inert-ready',
                   'venueDomainRuntimePhase':'inert-ready','venueRuntimeEnvPhase':'inert-ready',
                   'venueCompositeMode':'retired-inert','status':'managers-ready',
                   'graphCleared':['root','isolated'],'managerStopped':[],
                   'installedUnits':[{}]*194,'retiredUnits':[{}]*194,
                   'venueRegistryPhase':'retired-inert','venueBuildBasePhase':'retired-inert',
                   'podmanImageCacheRetired':True}
    def run_first_step(self):
        with (patch.object(module,'context',return_value=(self.bundle,self.ledger,self.plan)),
              patch.object(module,'receipt',return_value=self.data),
              patch.object(module.stage,'write_ledger') as write,
              patch.object(module.envs,'retire',side_effect=RuntimeError('next guarded step'))):
            try:module.retire('bundle','selector','inventory','ledger')
            except RuntimeError as exc:self.assertEqual(str(exc),'next guarded step')
            return write.call_count
    def test_completed_retirement_adopted_before_next_guarded_phase(self):
        self.assertEqual(self.run_first_step(),1)
        self.assertEqual(self.data['venueInstallerPhase'],'retiring')
    def test_partial_graph_or_missing_unit_receipt_refused_prewrite(self):
        for field,invalid in (('graphCleared',['root']),('retiredUnits',[{}]*193),
                              ('managerStopped',['isolated']),('venueBuildBasePhase','preparing')):
            with self.subTest(field=field):
                saved=self.data[field];self.data[field]=invalid
                self.data['venueInstallerPhase']='inert-ready'
                with self.assertRaises(module.Refusal):self.assertEqual(self.run_first_step(),0)
                self.data[field]=saved

class NativeHostRetirement(unittest.TestCase):
    def setUp(self):
        base=AdoptCompletedComposite();base.setUp()
        self.bundle,self.ledger,self.plan,self.data=base.bundle,base.ledger,base.plan,base.data
        self.plan['quadletTreeSha256']='tree'
        self.data.update(venueInstallerVersion=2,venueInstallerPhase='retiring',
                         venueRuntimeEnvPhase='retired-inert',venueStartHostContextSha256='context')
        rows=[{'path':'owned-'+str(i)} for i in range(65)]
        self.data['venueOwnedReset']={'phase':'empty-owned','quadletTreeSha256':'tree',
            'contextSha256':'context','directories':rows,'emptied':[r['path'] for r in rows],
            'networks':{'network':{'id':'native-id'}},'retiredNetworks':['native-id']}
    def invoke(self,refuse=False):
        events=[]
        def host(*args):
            self.assertEqual(args,(self.bundle,'selector',self.ledger,'reviewed-sha'))
            events.append('host-units')
            if refuse:raise module.Refusal('foreign host unit')
        def managers(*args,**kwargs):
            self.assertEqual(kwargs,{'stop':True});events.append('managers')
            raise RuntimeError('next guarded step')
        with (patch.object(module,'context',return_value=(self.bundle,self.ledger,self.plan)),
              patch.object(module,'receipt',return_value=self.data),
              patch.object(module.stage,'sha',return_value='reviewed-sha'),
              patch.object(module,'load',return_value=SimpleNamespace(retire_host_units=host)),
              patch.object(module.managers,'act',side_effect=managers)):
            with self.assertRaises(module.Refusal if refuse else RuntimeError):
                module.retire('bundle','selector','inventory','ledger')
        return events
    def test_native_units_retire_before_manager_empty_unit_gate(self):
        self.assertEqual(self.invoke(),['host-units','managers'])
    def test_completed_native_unit_receipt_is_not_replayed(self):
        self.data['venueHostUnitsRetirement']={'phase':'retired'}
        self.assertEqual(self.invoke(),['managers'])
    def test_never_active_version_one_does_not_retire_native_units(self):
        self.data['venueInstallerVersion']=1
        self.assertEqual(self.invoke(),['managers'])
    def test_host_unit_refusal_stops_before_manager_mutation(self):
        self.assertEqual(self.invoke(refuse=True),['host-units'])
        self.assertEqual(self.data['status'],'managers-ready')

if __name__=='__main__':unittest.main()
