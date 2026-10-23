#!/usr/bin/env python3
"""Root-owned temporary storage fixtures only; no account/service/app mutation."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/grant-rootless-volume-parent-traverse.py'
spec = importlib.util.spec_from_file_location('storage_fixture', SOURCE)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
REAL_LOOKUP = pwd.getpwnam


@unittest.skipUnless(os.geteuid() == 0, 'isolated root ACL fixtures require sudo')
class Storage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name); self.base.chmod(0o711)
        self.bundle = self.base / 'bundle'; (self.bundle / 'site').mkdir(parents=True)
        self.scope = self.base / 'scope'; self.scope.mkdir(mode=0o700)
        uid = REAL_LOOKUP('nobody').pw_uid
        self.account = SimpleNamespace(pw_uid=uid, pw_gid=REAL_LOOKUP('nobody').pw_gid, pw_dir='/home/nobody')
        self.row = {'name': 'fixture', 'user': 'nobody', 'uid': uid,
                    **{key: str(self.scope / directory / 'fixture') for key, directory in
                       (('stateRoot', 'state'), ('graphRoot', 'graphs'), ('volumeRoot', 'volumes'))}}
        self.manifest = {'schemaVersion': 2, 'site': 'fixture', 'deploymentMode': 'standalone',
                         'storageScope': {'root': str(self.scope), 'dataClass': 'synthetic'}}
        self.ir = {'services': {'forgejo-runner': {'rootlessDomain': 'fixture'}}, 'volumes': {}}
        self.seal()

    def save(self, name, body):
        raw = json.dumps(body).encode(); (self.bundle / name).write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def seal(self):
        manifest = self.save('site/manifest.json', self.manifest)
        ir = self.save('stack.ir.json', self.ir)
        source = self.save('source-provenance.json', {'manifestSha256': manifest})
        self.save('bundle.json', {'backend': 'podman', 'deploymentMode': 'standalone',
                                 'irSha256': ir, 'sourceProvenanceSha256': source})
        self.save('podman-domains.json', {'schemaVersion': 1, 'deploymentMode': 'standalone',
                                        'domains': [self.row], 'storageScope': self.manifest['storageScope']})

    def absent(self, name):
        if name == 'nobody': raise KeyError(name)
        return REAL_LOOKUP(name)

    def present(self, name):
        return self.account if name == 'nobody' else REAL_LOOKUP(name)

    def prepare(self, dry_run=False):
        # Model an absent installation account without changing the host passwd DB.
        with patch.object(m.pwd, 'getpwnam', self.absent), patch.object(m.grp, 'getgrnam', side_effect=KeyError):
            return m.prepare_scope(self.bundle, dry_run=dry_run)

    def test_dry_run_and_atomic_empty_scope_claim(self):
        self.prepare(True); self.assertEqual(list(self.scope.iterdir()), [])
        self.assertTrue(self.prepare())
        info = (self.scope / m.MARKER).stat()
        self.assertEqual(info.st_uid, 0); self.assertEqual(info.st_mode & 0o777, 0o600)
        self.assertEqual(info.st_nlink, 1)
        with patch.object(m.pwd, 'getpwnam', self.present):
            self.assertFalse(m.prepare_scope(self.bundle))
        self.assertEqual([p.name for p in self.scope.iterdir()], [m.MARKER])

    def test_root_owned_installed_bundle_retains_operator_owned_scope(self):
        operator = m.pwd.getpwnam('daemon')
        os.chown(self.scope, operator.pw_uid, operator.pw_gid)
        self.prepare()
        with patch.object(m.pwd, 'getpwnam', self.present):
            self.assertFalse(m.prepare_scope(self.bundle))
        self.assertEqual(self.scope.stat().st_uid, operator.pw_uid)

    def test_nonempty_unclaimed_data_and_existing_identity_are_not_adopted(self):
        authored = self.scope / 'authored-fixture'; authored.write_bytes(b'synthetic fixture')
        before = authored.stat()
        with self.assertRaisesRegex(ValueError, 'Nonempty'): self.prepare()
        self.assertEqual(authored.stat().st_uid, before.st_uid)
        self.assertFalse((self.scope / m.MARKER).exists())
        authored.unlink()
        with patch.object(m.pwd, 'getpwnam', self.present):
            with self.assertRaisesRegex(ValueError, 'Unclaimed existing'): m.prepare_scope(self.bundle)

    def test_escaping_or_linked_storage_is_refused_before_claim(self):
        self.row['graphRoot'] = str(self.base / 'foreign'); self.seal()
        with self.assertRaisesRegex(ValueError, 'escapes'): self.prepare()
        self.row['graphRoot'] = str(self.scope / 'linked' / 'fixture'); self.seal()
        (self.scope / 'linked').symlink_to(self.base)
        with self.assertRaisesRegex(ValueError, 'Linked'): self.prepare()
        self.assertFalse((self.scope / m.MARKER).exists())

    def test_exact_state_graph_volume_parent_traversal_and_private_sibling(self):
        self.prepare()
        for key in ('stateRoot', 'graphRoot', 'volumeRoot'):
            path = Path(self.row[key]); path.parent.mkdir(mode=0o700); path.mkdir(mode=0o700)
            os.chown(path, self.account.pw_uid, self.account.pw_gid)
        private = self.scope / 'private-sibling'; private.mkdir(mode=0o700)
        with patch.object(m.pwd, 'getpwnam', self.present):
            self.assertTrue(m.grant_standalone(self.bundle, 'fixture', 'nobody', Path(self.row['volumeRoot'])))
            self.assertFalse(m.grant_standalone(self.bundle, 'fixture', 'nobody', Path(self.row['volumeRoot'])))
        for key in ('stateRoot', 'graphRoot', 'volumeRoot'):
            self.assertEqual(subprocess.run(['runuser', '-u', 'nobody', '--', 'test', '-x', self.row[key]]).returncode, 0)
        self.assertNotEqual(subprocess.run(['runuser', '-u', 'nobody', '--', 'test', '-x', str(private)]).returncode, 0)
        self.assertEqual(m.entries(self.scope).get(('user', 'nobody')), '--x')
        self.assertEqual(self.scope.stat().st_mode & 0o007, 0)

    def test_ssh_setup_never_takes_over_nonempty_foreign_keys(self):
        self.prepare(); state = Path(self.row['stateRoot']); state.mkdir(parents=True)
        ssh = state / 'forgejo-runner-ssh'; ssh.mkdir(mode=0o700)
        (ssh / 'fixture-not-a-key').write_bytes(b'synthetic')
        with patch.object(m.pwd, 'getpwnam', self.present):
            with self.assertRaisesRegex(ValueError, 'pre-existing SSH'): m.prepare_ci_ssh(self.bundle)
            self.assertEqual(ssh.stat().st_uid, 0)
            (ssh / 'fixture-not-a-key').unlink()
            m.prepare_ci_ssh(self.bundle)
        self.assertEqual(ssh.stat().st_uid, self.account.pw_uid)
        self.assertEqual(ssh.stat().st_mode & 0o7777, 0o700)


if __name__ == '__main__': unittest.main()
