#!/usr/bin/env python3
"""Selected canonical marker reader: real FDs, model UID/ACL, no publisher authority."""
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import unittest

base = Path(__file__).absolute().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), m.__dict__)
    return m
f = load('native_file_marker_fixture', base / 'scripts/test-native-projection-marker.py')
m = load('native_file_marker_reader', base / 'runtime-generator/podman-ops/native-install-files.py')
m.o = f.v.o
m.p, m.native, m.storage = m.o.p, m.o.native, m.o.storage
m.require, m.Refused = m.o.require, m.o.Refused

class MarkerReader(f.Marker):
    def reader(self):
        # Deliberately ONLY exercise the actual root_read policy, not fabricate
        # a completed Session or one-use publication lease.
        s = m.Session.__new__(m.Session)
        s.fds = []; s.read_dirs = {}; s.marker_fd = None
        s.scope_fd = s.hold(os.open(self.scope, m.DIR))
        s.operator = SimpleNamespace(pw_uid=1000, pw_gid=1000)
        self.addCleanup(lambda: [os.close(fd) for fd in reversed(s.fds)])
        return s

    def test_native_marker_read_repeat_preserves_exact_acl(self):
        marker = self.native_marker(); s = self.reader()
        first = s.root_read(s.scope_fd, m.storage.MARKER, private=True)
        self.assertEqual(first, s.root_read(s.scope_fd, m.storage.MARKER, private=True))
        self.assertEqual(first[1]['acl'], f.marker_acl().hex())
        self.assertEqual(self.acls[self.key(marker)], (f.marker_acl(), b''))

    def test_foreign_latent_uid_refused(self):
        marker = self.native_marker(); self.acls[self.key(marker)] = f.marker_acl(uid=1001), b''
        s = self.reader()
        with self.assertRaises(ValueError): s.root_read(s.scope_fd, m.storage.MARKER, private=True)

    def test_nonzero_marker_mask_refused(self):
        marker = self.native_marker(); self.acls[self.key(marker)] = f.marker_acl(mask=4), b''
        s = self.reader()
        with self.assertRaises(ValueError): s.root_read(s.scope_fd, m.storage.MARKER, private=True)

    def test_foreign_gid_refused(self):
        marker = self.native_marker(); self.set_owner(marker, 0, 1001); s = self.reader()
        with self.assertRaises(ValueError): s.root_read(s.scope_fd, m.storage.MARKER, private=True)

    def test_other_root_input_stays_gid0_noacl(self):
        self.native_marker(); s = self.reader()
        path = self.scope / 'other-input'; path.write_bytes(b'{}'); path.chmod(0o600)
        self.set_owner(path, 0, 1000); self.acls[self.key(path)] = f.marker_acl(), b''
        with self.assertRaises(ValueError): s.root_read(s.scope_fd, path.name, private=True)

    def test_same_marker_name_outside_selected_scope_refused(self):
        self.native_marker(); s = self.reader()
        directory = self.scope / 'other-scope'; directory.mkdir(mode=0o700)
        marker = directory / m.storage.MARKER; marker.write_bytes(b'{}'); marker.chmod(0o600)
        self.set_owner(marker, 0, 1000); self.acls[self.key(marker)] = f.marker_acl(), b''
        fd = s.hold(os.open(directory, m.DIR))
        with self.assertRaises(ValueError): s.root_read(fd, m.storage.MARKER, private=True)

    def test_original_held_marker_not_rebased_after_replacement(self):
        marker = self.native_marker(); s = self.reader(); s.root_read(s.scope_fd, m.storage.MARKER, private=True)
        data = marker.read_bytes(); marker.rename(self.scope / 'old-marker')
        marker.write_bytes(data); marker.chmod(0o600); self.native_marker()
        with self.assertRaises(ValueError): s.root_read(s.scope_fd, m.storage.MARKER, private=True)

if __name__ == '__main__':
    suite = unittest.TestSuite(MarkerReader(n) for n in sorted(MarkerReader.__dict__) if n.startswith('test_'))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
