#!/usr/bin/env python3
"""Execute owning installer's embedded Python only, inside root temp fixtures."""
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/install-podman-bundle.sh'
TEXT = SOURCE.read_text()


def program(name):
    body = TEXT.split(name + '() {', 1)[1].split('\n}\n', 1)[0]
    return body.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]


class RangeTable(unittest.TestCase):
    def test_allocated_range_is_used_by_later_initialization_and_mismatch_refused(self):
        start = TEXT.index('  current_subuid="$(awk -F: -v user="$user" \'$1 == user && $3 >= 65536')
        script = TEXT[start:TEXT.index('  loginctl enable-linger', start)]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp); (path / 'uid').write_text('fixture:3000000:65536\n')
            (path / 'gid').write_text('fixture:3000000:65536\n')
            script = script.replace('/etc/subuid', str(path / 'uid')).replace('/etc/subgid', str(path / 'gid'))
            shell = 'set -e; user=fixture; index=0; declare -a ROOTLESS_DOMAIN_SUBUID_STARTS;\n' + script
            subprocess.run(['bash', '-c', shell + '\n[ "${ROOTLESS_DOMAIN_SUBUID_STARTS[0]}" = 3000000 ]'], check=True)
            (path / 'gid').write_text('fixture:4000000:65536\n')
            result = subprocess.run(['bash', '-c', shell], capture_output=True)
            self.assertNotEqual(result.returncode, 0)


@unittest.skipUnless(os.geteuid() == 0, 'root-owned temporary fixture only')
class PrivateVolumes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name); self.leaf = self.base / 'volume'
        self.uid = pwd.getpwnam('nobody').pw_uid; self.gid = pwd.getpwnam('nobody').pw_gid
        self.subid = 10000000

    def run_program(self, name, check=True):
        return subprocess.run([sys.executable, '-B', '-c', program(name), str(self.leaf),
                               str(self.uid), str(self.gid), str(self.subid)],
                              capture_output=True, check=check)

    def test_fresh_empty_leaf_only_is_initialized(self):
        self.run_program('prepare_standalone_private_volume')
        info = self.leaf.stat(); self.assertEqual((info.st_uid, info.st_gid), (self.uid, self.gid))
        self.assertEqual(info.st_mode & 0o7777, 0o711)

    def test_existing_shifted_ownership_modes_and_authored_child_are_unchanged(self):
        self.leaf.mkdir(mode=0o700); os.chown(self.leaf, self.subid + 999, self.subid + 999)
        child = self.leaf / 'synthetic-authored-fixture'; child.write_bytes(b'fixture')
        os.chown(child, 1000, 1000); child.chmod(0o600)
        before = [(p.lstat().st_uid, p.lstat().st_gid, p.lstat().st_mode) for p in (self.leaf, child)]
        self.run_program('prepare_standalone_private_volume')
        self.assertEqual(before, [(p.lstat().st_uid, p.lstat().st_gid, p.lstat().st_mode) for p in (self.leaf, child)])

    def test_linked_root_and_nonempty_foreign_ownership_are_refused(self):
        foreign = self.base / 'foreign'; foreign.mkdir(mode=0o700)
        self.leaf.symlink_to(foreign)
        self.assertNotEqual(self.run_program('prepare_standalone_private_volume', False).returncode, 0)
        self.assertEqual(foreign.stat().st_uid, 0); self.assertEqual(foreign.stat().st_mode & 0o777, 0o700)
        self.leaf.unlink(); self.leaf.mkdir(mode=0o700)
        (self.leaf / 'fixture').write_bytes(b'fixture')
        self.assertNotEqual(self.run_program('prepare_standalone_private_volume', False).returncode, 0)
        self.assertEqual(self.leaf.stat().st_uid, 0)

    def test_legacy_translation_preserves_already_translated_ids_on_repetition(self):
        self.leaf.mkdir(mode=0o700)
        current = self.leaf / 'current'; current.write_bytes(b'fixture'); os.chown(current, self.uid, self.gid)
        mapped = self.leaf / 'mapped'; mapped.write_bytes(b'fixture'); os.chown(mapped, self.subid + 999, self.subid + 999)
        self.run_program('translate_rootless_volume_owner')
        before = [(p.lstat().st_uid, p.lstat().st_gid) for p in (self.leaf, current, mapped)]
        self.run_program('translate_rootless_volume_owner')
        self.assertEqual(before, [(p.lstat().st_uid, p.lstat().st_gid) for p in (self.leaf, current, mapped)])
        self.assertEqual(current.stat().st_uid, self.uid); self.assertEqual(mapped.stat().st_uid, self.subid + 999)


if __name__ == '__main__': unittest.main()
