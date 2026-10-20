#!/usr/bin/env python3
"""Hostile fixture for exclusive rootless build pause release."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

MODULE=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-pause-release.py'
spec=importlib.util.spec_from_file_location('venue_pause_release',MODULE)
pause=importlib.util.module_from_spec(spec);spec.loader.exec_module(pause)
class PauseFixture(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.g=self.root/'graph';self.g.mkdir();os.chown(self.g,3206,3206)
        self.account={'name':'p0test-r1-test-runners','uid':3206,'graph':str(self.g)}
        self.plan={'prefix':'p0test-r1','accounts':[self.account]}
        info=self.g.stat();self.image='sha256:'+'a'*64
        self.data={'plan':self.plan,'status':'managers-ready','venueCompositeMode':'retiring',
            'retiredUnits':[str(n) for n in range(190)],'managerStopped':[],
            'activationAuthorized':False,'pathIdentities':{str(self.g):{
                'dev':info.st_dev,'ino':info.st_ino,'uid':3206}},
            'venueLocalBuildOutputs':{self.account['name']+'|output':self.image}}
        self.ledger=self.root/'ledger';self.ledger.write_text(json.dumps(self.data));self.ledger.chmod(0o600)
        self.before={'containers':[],'pods':[],'volumes':[],'images':{self.image},'networks':{'podman'}}
        self.identity={'pid':32323,'uid':3206,'startTicks':'76543','cgroup':'exact'}
    def exercise(self,**overrides):
        funcs={'geteuid':patch.object(pause.os,'geteuid',return_value=0),
            'owned_plan':patch.object(pause.stage,'owned_plan',return_value=self.plan),
            'pause_identity':patch.object(pause,'pause_identity',return_value=self.identity),
            'mount':patch.object(pause,'mounted_by_other_processes'),
            'stores':patch.object(pause.graph,'stores',return_value=[(self.account['name'],str(self.g),['selected'])]),
            'inspect':patch.object(pause.graph,'inspect_graph',return_value=self.before),
            'run':patch.object(pause.graph,'run',return_value=SimpleNamespace(returncode=0)),
            'write':patch.object(pause.stage,'write_ledger',side_effect=lambda p,d:self.ledger.write_text(json.dumps(d)))}
        funcs.update(overrides)
        with funcs['geteuid'],funcs['owned_plan'],funcs['pause_identity'],funcs['mount'],funcs['stores'],funcs['inspect'],funcs['run'] as run,funcs['write']:
            return pause.release(self.root,self.root,self.ledger,32323),run
    def test_only_exact_graph_migration_preserves_images_and_journals(self):
        result,run=self.exercise()
        self.assertEqual(result['imageIdsBeforeRelease'],1)
        self.assertEqual(json.loads(self.ledger.read_text())['venuePauseReleasePhases'][self.account['name']],'released')
        run.assert_called_once_with(['selected','system','migrate'],timeout=180)
    def test_foreign_image_refused_before_migration(self):
        self.before['images'].add('sha256:'+'f'*64)
        with patch.object(pause.os,'geteuid',return_value=0),patch.object(pause.stage,'owned_plan',return_value=self.plan),patch.object(pause,'pause_identity',return_value=self.identity),patch.object(pause,'mounted_by_other_processes'),patch.object(pause.graph,'stores',return_value=[(self.account['name'],str(self.g),['selected'])]),patch.object(pause.graph,'inspect_graph',return_value=self.before),patch.object(pause.graph,'run') as run:
            with self.assertRaisesRegex(pause.Refusal,'unreviewed/missing'):
                pause.release(self.root,self.root,self.ledger,32323)
            run.assert_not_called()
    def test_wrong_stage_refuses_before_any_graph_call(self):
        self.data['retiredUnits'].pop();self.ledger.write_text(json.dumps(self.data))
        with patch.object(pause.os,'geteuid',return_value=0),patch.object(pause.stage,'owned_plan',return_value=self.plan),patch.object(pause.graph,'inspect_graph') as inspect:
            with self.assertRaisesRegex(pause.Refusal,'fully stopped'):
                pause.release(self.root,self.root,self.ledger,32323)
            inspect.assert_not_called()
    def test_unselected_mount_or_pause_identity_refused(self):
        with patch.object(pause.os,'geteuid',return_value=0),patch.object(pause.stage,'owned_plan',return_value=self.plan),patch.object(pause,'pause_identity',side_effect=pause.Refusal('foreign pause')):
            with self.assertRaisesRegex(pause.Refusal,'foreign pause'):
                pause.release(self.root,self.root,self.ledger,32323)
if __name__=='__main__':unittest.main()
