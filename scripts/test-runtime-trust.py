#!/usr/bin/env python3
"""Isolated root fixtures, never installed application/security acceptance."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

path=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/runtime-trust.py'
spec=importlib.util.spec_from_file_location('runtime_trust_fixture',path)
trust=importlib.util.module_from_spec(spec);spec.loader.exec_module(trust)

@unittest.skipUnless(os.geteuid()==0,'isolated ownership/denial fixtures require root')
class Trust(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o755)
        self.private=self.root/'private';self.public=self.root/'public';self.target=self.root/'leaf'
        for p in (self.private,self.public,self.target):p.mkdir(mode=0o750)
        self.key=self.root/'fixture.key';self.cert=self.root/'fixture.crt'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-subj','/CN=mail.example.test','-addext','subjectAltName=DNS:mail.example.test',
            '-addext','basicConstraints=critical,CA:FALSE','-keyout',str(self.key),'-out',str(self.cert)],
            check=True,capture_output=True,timeout=20)
        self.key.chmod(0o600);self.cert.chmod(0o644)
        (self.public/'caddy-ca.crt').write_bytes(self.cert.read_bytes())
        (self.private/'root.key').write_bytes(self.key.read_bytes());(self.private/'root.key').chmod(0o600)
    def tearDown(self):self.tmp.cleanup()
    def actor(self,code):
        return subprocess.run(['setpriv','--reuid=65533','--regid=65533','--clear-groups',
            'python3','-B','-c',code],capture_output=True,timeout=10).returncode
    def test_public_certificate_only_and_private_key_denial(self):
        trust.prepare(self.private,self.public,self.target)
        self.assertEqual(self.actor(f'open({str(self.public/"caddy-ca.crt")!r}).read()'),0)
        self.assertNotEqual(self.actor(f'open({str(self.public/"caddy-ca.crt")!r},"ab").write(b"x")'),0)
        self.assertNotEqual(self.actor(f'open({str(self.private/"root.key")!r},"rb").read()'),0)
        (self.public/'caddy-ca.crt').write_bytes(self.key.read_bytes())
        with self.assertRaises(ValueError):trust.prepare(self.private,self.public,self.target)
    def test_atomic_leaf_pair_and_no_ca_private_delegation(self):
        cert,key=self.cert.read_bytes(),self.key.read_bytes()
        trust.validate_leaf(cert,key,'mail.example.test')
        with self.assertRaises(ValueError):trust.validate_leaf(cert,key,'other.example.test')
        trust.prepare(self.private,self.public,self.target)
        name=trust.publish(self.target,cert,key,65533)
        self.assertEqual(os.readlink(self.target/'current'),'generations/'+name)
        self.assertEqual((self.target/'current/key.pem').read_bytes(),key)
        self.assertEqual(self.actor(f'open({str(self.target/"current/key.pem")!r},"rb").read()'),0)
        self.assertNotEqual(self.actor(f'open({str(self.target/"current/key.pem")!r},"ab").write(b"x")'),0)
        self.assertNotEqual(self.actor(f'open({str(self.private/"root.key")!r},"rb").read()'),0)
        self.assertEqual(trust.publish(self.target,cert,key,65533),name)
        self.assertEqual(len(list((self.target/'generations').iterdir())),1)
    def test_links_and_foreign_artifacts_refused(self):
        (self.public/'unexpected.key').write_bytes(b'synthetic-not-a-key')
        with self.assertRaises(ValueError):trust.prepare(self.private,self.public,self.target)
        (self.public/'unexpected.key').unlink();(self.public/'caddy-ca.crt').unlink()
        (self.public/'caddy-ca.crt').symlink_to(self.cert)
        with self.assertRaises((ValueError,OSError)):trust.prepare(self.private,self.public,self.target)
        (self.public/'caddy-ca.crt').unlink();(self.public/'caddy-ca.crt').symlink_to(self.root/'absent')
        with self.assertRaises((ValueError,OSError)):trust.prepare(self.private,self.public,self.target)
    def test_private_ca_cannot_be_published_as_leaf(self):
        ca=self.root/'ca.crt'
        subprocess.run(['openssl','req','-x509','-new','-key',str(self.key),'-days','1',
            '-subj','/CN=mail.example.test','-addext','subjectAltName=DNS:mail.example.test',
            '-addext','basicConstraints=critical,CA:TRUE','-out',str(ca)],check=True,capture_output=True)
        with self.assertRaises(ValueError):trust.validate_leaf(ca.read_bytes(),self.key.read_bytes(),'mail.example.test')

if __name__=='__main__':unittest.main()
