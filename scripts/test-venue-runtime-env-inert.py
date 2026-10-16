#!/usr/bin/env python3
"""Refuse ambiguous sealed env inputs before creating any runtime file."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
spec=importlib.util.spec_from_file_location('venue_env',Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-runtime-env-inert.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

@unittest.skipUnless(os.geteuid()==0,'protected aggregate fixture')
class EnvParser(unittest.TestCase):
    def test_expansion_is_bounded_and_does_not_employ_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'stack.env';p.write_text('A=${B}\nB=sealed\n');p.chmod(0o600)
            values=module.env_values(p)
            self.assertEqual(module.expand('${A:?required}',values),'sealed')
            self.assertEqual(module.expand('${MISSING:-fallback}',values),'fallback')
            with self.assertRaises(module.Refusal):module.expand('${MISSING:?required}',values)
            with self.assertRaises(module.Refusal):module.expand('${A}\nSPOOF=bad',values)
            p.write_text('FORGEJO__database__HOST=local\ndiscovery.type=single-node\n')
            self.assertEqual(module.env_values(p)['discovery.type'],'single-node')
            p.write_text('A=x\nA=y\n')
            with self.assertRaises(module.Refusal):module.env_values(p)
    def test_aggregate_requires_exact_root0600_regular_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'stack.env';p.write_text('A=sealed\n');p.chmod(0o644)
            with self.assertRaises(module.Refusal):module.env_values(p)
            p.chmod(0o600);link=Path(tmp)/'linked';link.symlink_to(p)
            with self.assertRaises(module.Refusal):module.env_values(link)

if __name__=='__main__':unittest.main()
