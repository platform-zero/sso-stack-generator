#!/usr/bin/env python3
"""Only an already fully retired, never-active composite can be adopted."""
import importlib.util
from pathlib import Path
from unittest.mock import patch
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

if __name__=='__main__':unittest.main()
