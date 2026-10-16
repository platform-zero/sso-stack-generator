#!/usr/bin/env python3
"""Exact FROM pin, no-pull alias and local graph-retirement refusals."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
here=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops'
spec=importlib.util.spec_from_file_location('venue_build_base_images',here/'venue-build-base-images.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)

class BuildBaseFixtures(unittest.TestCase):
    def setUp(self):
        self.user='p0test-r1-apps';self.ref='docker.io/library/python:3.12-slim'
        self.pair=self.user+'|'+self.ref;self.digest='sha256:'+'1'*64;self.config='sha256:'+'2'*64
        self.pins={self.pair:{'registryReference':self.ref,'linuxAmd64ManifestDigest':self.digest,
                              'configId':self.config}}
        self.source={'buildBaseImages':self.pins}
    def test_pinned_mutable_base_is_fetched_by_manifest_then_tagged_locally(self):
        alias={};calls=[]
        def identify(command,ref):return alias.get(ref)
        def fetch(command,ref):
            calls.append(('fetch',ref));alias[ref]=self.config
        def run(command,**kwargs):
            calls.append(('tag',command[-2:]));alias[self.ref]=alias[command[-2]]
            return SimpleNamespace(returncode=0,stdout='')
        with (patch.object(base,'identity',side_effect=identify),patch.object(base.registry,'fetch',side_effect=fetch),
              patch.object(base.graph,'run',side_effect=run)):
            self.assertEqual(base.fetch_selected(['selected-store'],self.pair,self.source),self.config)
        self.assertEqual(calls,[('fetch',self.ref+'@'+self.digest),
                                ('tag',[self.ref+'@'+self.digest,self.ref])])
    def test_wrong_tag_or_manifest_config_refuses_without_tagging(self):
        with patch.object(base,'identity',return_value='sha256:'+'f'*64):
            with self.assertRaisesRegex(base.Refusal,'another config'):
                base.fetch_selected(['selected-store'],self.pair,self.source)
        with (patch.object(base,'identity',side_effect=lambda _cmd,ref:None if ref==self.ref else 'sha256:'+'f'*64),
              patch.object(base.registry,'fetch',return_value=None),
              patch.object(base.graph,'run',side_effect=AssertionError('tag must not run'))):
            with self.assertRaisesRegex(base.Refusal,'config ID differs'):
                base.fetch_selected(['selected-store'],self.pair,self.source)
    def test_graph_retirement_checks_from_alias_and_arch_before_image_deletion(self):
        graph=base.graph
        immutable='docker.io/example/base@sha256:'+'3'*64
        known={self.pair:self.config,self.user+'|'+immutable:'sha256:'+'4'*64}
        source={'buildBaseStores':sorted(known),'frozenBuildBaseSha256':'5'*64,
                'buildBaseImages':self.pins}
        state={'venueBuildBasePhase':'inert-ready','venueRegistryPhase':'inert-ready',
               'venueBuildBasePlan':sorted(known),'venueBuildBaseFrozenSha256':'5'*64,
               'venueBuildBaseVerified':known}
        def podman(command,**kwargs):
            if command[-2]=='{{.Architecture}}/{{.Os}}':return SimpleNamespace(returncode=0,stdout='amd64/linux\n')
            image=command[-1];value=known.get(self.user+'|'+image)
            return SimpleNamespace(returncode=0,stdout=value+'\n' if value else 'wrong\n')
        with (patch.object(graph.stage,'owned_plan',return_value={'accounts':[]}),
              patch.object(graph,'stores',return_value=[(self.user,'/unused',['selected-store'])]),
              patch.object(graph,'run',side_effect=podman)):
            self.assertEqual(graph.journaled_build_base_ids('bundle','selector',state,source)[self.user],set(known.values()))
            state['venueBuildBasePending']=self.pair
            with self.assertRaisesRegex(graph.Refusal,'journal lacks'):
                graph.journaled_build_base_ids('bundle','selector',state,source)
            del state['venueBuildBasePending']
            known[self.pair]='sha256:'+'f'*64
            with self.assertRaisesRegex(graph.Refusal,'config ID differs'):
                graph.journaled_build_base_ids('bundle','selector',state,source)

if __name__=='__main__':unittest.main()
