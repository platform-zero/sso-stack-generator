#!/usr/bin/env python3
"""Hostile complete-image and local-build authority fixtures, no pulls."""
import importlib.util
import json
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
src=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-image-authority.py'
spec=importlib.util.spec_from_file_location('venue_image_authority',src)
authority=importlib.util.module_from_spec(spec);spec.loader.exec_module(authority)

class ImageAuthority(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.b=Path(tmp.name);self.root=self.b/'quadlet/rootful';self.root.mkdir(parents=True)
        self.site=self.b/'site/global.settings';self.site.mkdir(parents=True)
        self.rows={}
        for i in range(60):
            ref=f'docker.io/selected/image{i}:v1@sha256:{i+1:064x}'
            image_id=f'sha256:{i+101:064x}'
            self.rows['root|'+ref]=image_id
            (self.root/f'p0test-r1-image-{i}.container').write_text('Image='+ref+'\n')
        for i in range(19):
            ref=list(self.rows)[i].split('|',1)[1]
            (self.root/f'p0test-r1-repeat-{i}.container').write_text('Image='+ref+'\n')
        for i in range(14):
            name=f'p0test-r1-build-{i}'
            (self.root/(name+'.container')).write_text('Image='+name+'.build\n')
            (self.root/(name+'.build')).write_text('[Build]\nImageTag=selected\n'
                f'SetWorkingDirectory="/tmp/current/build/{name}"\nFile="Containerfile"\nPull=never\n')
            source=self.b/'build'/name;source.mkdir(parents=True)
            (source/'Containerfile').write_text('FROM docker.io/selected/base:1@sha256:'+'f'*64+'\n')
        self.pins=self.site/'registry-image-ids.json';self.pins.write_text(json.dumps(self.rows))
        self.plan={'sourceCommit':'a'*40,'bundleIrSha256':'b'*64,
                   'quadletTreeSha256':'c'*64,'selectorSha256':'d'*64,
                   'accounts':[{'name':'p0test-r1-'+n} for n in ('platform','apps','homeassistant','vaultwarden','ci-runner','workloads','test-runners')],
                   'prefix':'p0test-r1'}
        patcher=patch.object(authority.stage,'owned_plan',return_value=self.plan);patcher.start();self.addCleanup(patcher.stop)
    def test_all_60_frozen_authorities_and_14_local_builds(self):
        r=authority.authority(self.b,'unused');self.assertEqual((r['containerUnits'],r['directImageReferences'],r['localBuildUnits']),(93,60,14))
        self.assertEqual(set(r['imageIds']),set(self.rows))
    def test_build_without_no_pull_refuses_pinned_activation(self):
        p=self.root/'p0test-r1-build-0.build'
        p.write_text(p.read_text().replace('Pull=never\n',''))
        with self.assertRaisesRegex(authority.Refusal,'may pull an unreviewed base'):
            authority.authority(self.b,'unused',require_pinned_bases=True)
    def test_missing_identity_or_selected_build_refuses(self):
        key=next(iter(self.rows));data=self.rows.copy();data.pop(key);self.pins.write_text(json.dumps(data))
        with self.assertRaises(authority.Refusal):authority.authority(self.b,'unused')
        self.pins.write_text(json.dumps(self.rows));(self.root/'p0test-r1-build-0.build').unlink()
        with self.assertRaises(authority.Refusal):authority.authority(self.b,'unused')
    def test_clean_site_pins_mutable_base_per_store_and_tampering_refuses(self):
        (self.b/'build/p0test-r1-build-0/Containerfile').write_text('FROM docker.io/library/python:3.12-slim\n')
        pins=self.site/'build-base-image-ids.json'
        approved={'schemaVersion':1,'platform':'linux/amd64','baseImages':{
            'root|docker.io/library/python:3.12-slim':{
                'registryReference':'docker.io/library/python:3.12-slim',
                'linuxAmd64ManifestDigest':'sha256:'+'d'*64,'configId':'sha256:'+'e'*64}}}
        pins.write_text(json.dumps(approved))
        checkout=self.b/'site-source';published=checkout/'sites/latium/global.settings'
        published.mkdir(parents=True)
        (published/'registry-image-ids.json').write_bytes(self.pins.read_bytes())
        (published/'build-base-image-ids.json').write_bytes(pins.read_bytes())
        def git(*args):subprocess.run(['git','-C',str(checkout),*args],check=True,capture_output=True)
        git('init','-q');git('add','.');subprocess.run(['git','-C',str(checkout),
            '-c','user.email=fixture@localhost','-c','user.name=Fixture','commit','-qm','pin'],
            check=True,capture_output=True)
        commit=subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip()
        (self.b/'source-provenance.json').write_text(json.dumps({'siteCommit':commit}))
        result=authority.authority(self.b,'unused',checkout,require_pinned_bases=True)
        self.assertEqual(result['frozenBuildBasePairs'],1)
        pins.write_text(pins.read_text()+' ')
        with self.assertRaisesRegex(authority.Refusal,'differ from clean pinned site'):
            authority.authority(self.b,'unused',checkout,require_pinned_bases=True)
    def test_mutable_local_build_base_refuses_when_pinning_required(self):
        self.assertEqual(authority.authority(self.b,'unused',require_pinned_bases=True)['mutableBuildBaseReferences'],[])
        (self.b/'build/p0test-r1-build-0/Containerfile').write_text('FROM docker.io/library/python:3.12-slim\n')
        self.assertEqual(authority.authority(self.b,'unused')['mutableBuildBaseReferences'],
                         ['docker.io/library/python:3.12-slim'])
        with self.assertRaisesRegex(authority.Refusal,'lack clean frozen'):
            authority.authority(self.b,'unused',require_pinned_bases=True)
    def test_unpinned_latest_refuses_even_if_identity_added(self):
        p=self.root/'p0test-r1-image-0.container';old=p.read_text().split('=',1)[1].strip()
        p.write_text('Image=docker.io/selected/image0:latest\n')
        data=self.rows.copy();data['root|docker.io/selected/image0:latest']=data.pop('root|'+old)
        self.pins.write_text(json.dumps(data))
        with self.assertRaises(authority.Refusal):authority.authority(self.b,'unused')

if __name__=='__main__':unittest.main()
