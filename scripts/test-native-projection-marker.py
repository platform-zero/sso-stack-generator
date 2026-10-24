#!/usr/bin/env python3
"""Finite marker-only private-ACL/HeldCAS regression; isolated real FDs/model IDs."""
import importlib.util
import os
from pathlib import Path
import struct
import time
import unittest

path = Path(__file__).with_name('test-native-runtime-projections.py')
spec = importlib.util.spec_from_file_location('marker_projection_fixture', path)
f = importlib.util.module_from_spec(spec)
exec(compile(path.read_bytes(), str(path), 'exec'), f.__dict__)
v = f.v


def marker_acl(*, uid=1000, mask=0, other=0):
    rows = ((1, 6, 0xffffffff), (2, 7, uid), (4, 7, 0xffffffff),
            (16, mask, 0xffffffff), (32, other, 0xffffffff))
    return struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *r) for r in rows)


class Marker(f.Projections):
    def native_marker(self):
        marker = self.scope / v.o.storage.MARKER
        self.set_owner(marker, 0, 1000)
        self.acls[self.key(marker)] = marker_acl(), b''
        return marker

    def snapshot(self):
        snapshot = v.Snapshot(self.install, self.release, self.intent, False, time.monotonic() + 110)
        self.addCleanup(snapshot.close)
        return snapshot

    def test_private_native_marker_preserved(self):
        marker = self.native_marker()
        before = marker.read_bytes(), self.acls[self.key(marker)], self.raw_lstat(marker)
        snapshot = self.snapshot(); binding = snapshot.candidate_binding()
        snapshot.final_controls(binding)
        after = marker.read_bytes(), self.acls[self.key(marker)], self.raw_lstat(marker)
        self.assertEqual(before[:2], after[:2])
        self.assertEqual((before[2].st_ino, before[2].st_mode, before[2].st_mtime_ns, before[2].st_ctime_ns),
                         (after[2].st_ino, after[2].st_mode, after[2].st_mtime_ns, after[2].st_ctime_ns))
        self.assertEqual(binding['marker_pin']['acl'], marker_acl().hex())

    def test_private_gid1000_noacl_marker(self):
        marker = self.native_marker(); self.acls[self.key(marker)] = b'', b''
        snapshot = self.snapshot(); snapshot.final_controls(snapshot.candidate_binding())

    def test_foreign_latent_uid_refused(self):
        marker = self.native_marker(); self.acls[self.key(marker)] = marker_acl(uid=1001), b''
        with self.assertRaises(ValueError): self.snapshot().candidate_binding()

    def test_nonzero_mask_refused(self):
        marker = self.native_marker(); self.acls[self.key(marker)] = marker_acl(mask=4), b''
        with self.assertRaises(ValueError): self.snapshot().candidate_binding()

    def test_marker_default_acl_refused(self):
        marker = self.native_marker(); self.acls[self.key(marker)] = marker_acl(), marker_acl()
        with self.assertRaises(ValueError): self.snapshot().candidate_binding()

    def test_foreign_gid_refused(self):
        marker = self.native_marker(); self.set_owner(marker, 0, 1001)
        with self.assertRaises(ValueError): self.snapshot().candidate_binding()

    def test_regular_receipt_still_refuses_same_masked_acl(self):
        self.native_marker(); receipt = self.release / 'installation-receipt.json'
        self.acls[self.key(receipt)] = marker_acl(), b''
        with self.assertRaises(ValueError): self.snapshot().candidate_binding()

    def test_same_bytes_marker_replacement_refused(self):
        marker = self.native_marker(); snapshot = self.snapshot(); binding = snapshot.candidate_binding()
        data = marker.read_bytes(); marker.rename(self.scope / 'old-marker')
        marker.write_bytes(data); marker.chmod(0o600); self.native_marker()
        with self.assertRaises(ValueError): snapshot.final_controls(binding)

    def test_held_marker_content_change_refused(self):
        marker = self.native_marker(); snapshot = self.snapshot(); binding = snapshot.candidate_binding()
        marker.write_bytes(marker.read_bytes() + b' ')
        with self.assertRaises(ValueError): snapshot.final_controls(binding)

    def test_final_scope_named_inode_replacement_refused(self):
        self.native_marker(); snapshot = self.snapshot(); binding = snapshot.candidate_binding()
        self.scope.rename(self.scope.with_name(self.scope.name + '-old'))
        self.scope.mkdir(mode=0o700)
        with self.assertRaises(ValueError): snapshot.final_controls(binding)


if __name__ == '__main__':
    suite = unittest.TestSuite(Marker(name) for name in sorted(Marker.__dict__) if name.startswith('test_'))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
