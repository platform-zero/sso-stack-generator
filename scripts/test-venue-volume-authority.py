#!/usr/bin/env python3
"""Hostile static actual-source/selector label divergence fixtures."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

src=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/inspect-venue-volume-authority.py'
spec=importlib.util.spec_from_file_location('volume_authority',src)
vol=importlib.util.module_from_spec(spec);spec.loader.exec_module(vol)

class VolumeAuthorityFixtures(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.bundle=self.root/'bundle';self.selector=self.root/'selector.json'
        self.rootful=self.root/'volumes';self.apps=self.root/'rootless/apps'
        self.q=self.bundle/'quadlet/rootful';self.a=self.bundle/'quadlet/rootless-apps'
        self.q.mkdir(parents=True);self.a.mkdir(parents=True)
        self.labels={'data'+str(i):str(self.rootful/('data'+str(i))) for i in range(55)}
        self.labels.update({name:str(self.apps/'graph/volumes'/name/'_data') for name in vol.NAMED})
        self.selector.write_text(json.dumps({'volumes':self.labels,'rootful':{'volumeRoot':str(self.rootful)}}))
        self.plan={'prefix':'p0test-r1','accounts':[{'name':'p0test-r1-apps','volume':str(self.apps)}]}
        for i in range(54):
            src=self.apps/'data0' if i==0 else self.rootful/('data'+str(i))
            dst=self.a if i==0 else self.q
            (dst/('p0test-r1-data'+str(i)+'.container')).write_text('Volume='+str(src)+':/data\n')
        (self.a/'p0test-r1-huly.container').write_text(''.join('Volume='+x+':/data\n' for x in sorted(vol.NAMED)))
    def test_actual_rootless_path_differs_from_selector_label(self):
        with patch.object(vol.stage,'owned_plan',return_value=self.plan):
            result=vol.inspect(self.bundle,self.selector)
        self.assertEqual(result['actualDataBindSources'],54)
        self.assertEqual(result['selectedVolumeLabels'],59)
        self.assertEqual(result['unreferencedSelectorLabels'],['data54'])
        self.assertEqual(result['pathDivergences']['data0'],[str(self.apps/'data0')])
        self.assertFalse(result['activationAuthorized'])
    def test_foreign_path_or_unknown_name_refuses(self):
        bad=self.q/'p0test-r1-data1.container';good=bad.read_text()
        bad.write_text('Volume=/tmp/foreign/data1:/data\n')
        with patch.object(vol.stage,'owned_plan',return_value=self.plan),self.assertRaises(vol.Refusal):
            vol.inspect(self.bundle,self.selector)
        bad.write_text(good+'Volume='+str(self.rootful/'foreign')+':/data\n')
        with patch.object(vol.stage,'owned_plan',return_value=self.plan),self.assertRaises(vol.Refusal):
            vol.inspect(self.bundle,self.selector)

if __name__=='__main__':unittest.main()
