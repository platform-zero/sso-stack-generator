#!/usr/bin/env python3
"""CAS refusal tests for exact failed-build Buildah working containers."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

MODULE=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-buildah-containers-retire.py'
spec=importlib.util.spec_from_file_location('failed_buildah',MODULE)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class BuildahFixture(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.p=Path(self.tmp.name)/'ledger';self.user='p0test-r1-test-runners';self.base='sha256:'+'a'*64
        self.failed=['sha256:'+c*64 for c in 'bcdef']
        self.plan={'prefix':'p0test-r1','accounts':[{'name':self.user}]}
        self.j={'plan':self.plan,'status':'graphs-clearing','venueCompositeMode':'retiring',
                'activationAuthorized':False,'graphCleared':[],
                'pendingGraphImageRemoval':{'user':self.user,'image':self.failed[-1]},
                'venueBuildBaseVerified':{self.user+'|debian:13-slim':self.base},
                'venueFailedBuildIntermediates':{self.user+'|localhost/webservices/android-test-runner-api34:bundle':self.failed}}
        self.p.write_text(json.dumps(self.j));self.p.chmod(0o600)
        self.rows=[]
        for i,img in enumerate([self.base]+self.failed):
            self.rows.append({'id':str(i)*64,'builder':True,'imageid':img[7:],
                              'containername':'debian-working-container' if i==0 else img[7:19]+'-working-container'})
    def call(self):
        calls=[]
        def run(command,**kw):
            calls.append(command)
            if 'containers' in command:return SimpleNamespace(returncode=0,stdout=json.dumps(self.rows))
            if 'rm' in command:
                self.rows[:]=[r for r in self.rows if r['id']!=command[-1]]
                return SimpleNamespace(returncode=0,stdout='')
            raise AssertionError(command)
        with patch.object(module.os,'geteuid',return_value=0),\
             patch.object(module.stage,'owned_plan',return_value=self.plan),\
             patch.object(module.graph,'stores',return_value=[(self.user,'graph',['env','podman'])]),\
             patch.object(module.graph,'run',side_effect=run):
            result=module.retire('bundle','selector',self.p)
        return result,calls
    def test_exact_six_only(self):
        result,calls=self.call()
        self.assertEqual(result['count'],6)
        self.assertEqual(len([x for x in calls if 'rm' in x]),6)
        self.assertFalse(self.rows)
    def test_foreign_seventh_refuses_before_removal(self):
        self.rows.append({'id':'9'*64,'builder':True,'imageid':'9'*64,'containername':'foreign'})
        with self.assertRaisesRegex(module.Refusal,'unselected or missing'):
            self.call()
        self.assertEqual(len(self.rows),7)
if __name__=='__main__':unittest.main()
