#!/usr/bin/env python3
"""Hostile inert Quadlet inventory tests; never install a systemd unit."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

source=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-unit-stage.py'
spec=importlib.util.spec_from_file_location('venue_units',source)
units=importlib.util.module_from_spec(spec);spec.loader.exec_module(units)

class InertUnitManifest(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.bundle=Path(temp.name);root=self.bundle/'quadlet'
        self.plan={'prefix':'p0test-r1','accounts':[{'name':'p0test-r1-'+d,'uid':3200+i,'home':'/home/p0test-r1-'+d}
                        for i,d in enumerate(('platform','apps','homeassistant','finance','ci-runner','workloads','test-runners'))]}
        for domain,count in (('rootful',16),('rootless-platform',33),('rootless-apps',74),
                             ('rootless-homeassistant',9),('rootless-finance',15),
                             ('rootless-ci-runner',7),('rootless-workloads',12),('rootless-test-runners',24)):
            folder=root/domain;folder.mkdir(parents=True)
            for i in range(count):
                ext='.target' if i==0 else '.container'
                (folder/(f'p0test-r1-{domain}-{i}'+ext)).write_text('[Unit]\nDescription=synthetic unit\n')
    def test_exact_190_disjoint_private_unit_destinations(self):
        result=units.manifest(self.bundle,self.plan)
        self.assertEqual(len(result),190)
        self.assertEqual(sum(p.startswith('/etc/') for p in result),16)
        self.assertEqual(sum(p.startswith('/home/') for p in result),174)
        self.assertTrue(all(v['sha256'] and len(v['sha256'])==64 for v in result.values()))
        self.assertFalse(any('webservices-' in p or '/run/p0-control' in p for p in result))
    def test_extra_duplicate_link_or_old_name_refuses(self):
        root=self.bundle/'quadlet/rootful';q=next(root.glob('*.container'));contents=q.read_text()
        for change in ('old-name','linked','extra','wrong-extension','missing'):
            if change=='old-name':
                q.rename(root/'webservices-old.container')
            elif change=='linked':
                q.unlink();q.symlink_to('/etc/passwd')
            elif change=='extra':
                (root/'p0test-r1-extra.container').write_text(contents)
            elif change=='wrong-extension':
                q.rename(root/'p0test-r1-unclassified.socket')
            else:q.unlink()
            with self.subTest(change=change),self.assertRaises(units.Refusal):units.manifest(self.bundle,self.plan)
            for bad in ('webservices-old.container','p0test-r1-extra.container','p0test-r1-unclassified.socket'):
                (root/bad).unlink(missing_ok=True)
            if q.is_symlink():q.unlink()
            q.write_text(contents)

if __name__=='__main__':unittest.main()
