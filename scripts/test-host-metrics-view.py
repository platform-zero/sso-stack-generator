#!/usr/bin/env python3
"""Temp-root ONLY: mocked ownership/mount facts, never host installation/probe.

No host proc/statvfs, app calls, containers, native commands, or credentials.
Real temporary directories exercise FD traversal, topology and proof publishing.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).absolute().parents[1] / 'runtime-generator/podman-ops/host-metrics-view.py'
SPEC = importlib.util.spec_from_file_location('host_views', SOURCE)
h = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(h)
MODULE = SOURCE.parents[2].parent / 'module-delivery/node-exporter'


class Views(unittest.TestCase):
    def setUp(self):
        previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, previous_umask)
        self.temp = tempfile.TemporaryDirectory(prefix='host-metrics-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.scope = self.base / 'scope'
        self.install = self.base / 'installer'
        self.bundle = self.install / 'releases/r1'
        self.root = self.bundle / 'runtime/configs/node-exporter/rootfs-view'
        self.stack = self.scope / 'volumes' / h.VOLUME
        self.marker = {'schemaVersion': 1, 'kind': 'standalone-stack-storage',
                       'scope': {'root': str(self.scope), 'dataClass': 'synthetic'}, 'domains': []}
        self.ir = {'services': {'node-exporter': dict(h.FIELDS | h.SERVICE_IDENTITY, image=h.IMAGE,
                   hostMetricsView='./configs/' + h.DESCRIPTOR,
                   volumes=h.MOUNTS, command=h.COMMAND)},
                   'volumes': {h.VOLUME: {'hostPath': str(self.stack), 'rootlessStrategy': 'shared'}}}
        self.put(self.scope / '.stack-installation.json', h.encoded(self.marker))
        self.put(self.bundle / 'bundle.json', b'{}\n')
        self.put(self.bundle / 'source-provenance.json', b'{}\n')
        self.put(self.bundle / 'podman-domains.json', h.encoded({'installerStateRoot': str(self.install)}))
        self.put(self.bundle / 'site/manifest.json', b'{}\n')
        descriptor = (MODULE / 'stack.config/node-exporter/host-metrics-view.json').read_bytes()
        self.put(self.bundle / 'stack.config' / h.DESCRIPTOR, descriptor)
        self.put(self.bundle / 'runtime/configs' / h.DESCRIPTOR, descriptor)
        self.stack.parent.mkdir(parents=True, mode=0o700)
        self.unit = self.bundle / 'quadlet/rootful/webservices-node-exporter.container'
        self.put(self.unit, ('[Container]\nImage=docker.io/' + h.IMAGE + '\nContainerName=node-exporter\n'
                 'User=65534:65534\nReadOnly=true\nDropCapability=ALL\n'
                 'NoNewPrivileges=true\nNetwork=host\nPodmanArgs=--image-volume=ignore --pid=host\n'
                 'Volume=' + str(self.install / 'current/runtime/configs/node-exporter/rootfs-view') + ':/host:ro\n'
                 'Volume=' + str(self.stack) + ':/host/mnt/stack:ro\n'
                 'Exec=' + ' '.join(json.dumps(v) for v in h.COMMAND) + '\n').encode())
        self.reseal()
        dev = self.base.stat().st_dev
        self.device = str(os.major(dev)) + ':' + str(os.minor(dev))
        self.native = self.mountinfo()
        self.inode_paths = {}
        self.fact_overrides = {}
        self.addCleanup(patch.stopall)
        patch.object(h, 'OWNER', os.getuid()).start()
        patch.object(h.os, 'geteuid', return_value=0).start()
        self.roles_mock = patch.object(h, 'role_authority', return_value=(self.scope, self.marker, {})).start()
        patch.object(h, 'mounts', side_effect=lambda: (self.native, self.native)).start()
        patch.object(h, 'host_devices', return_value={
            '/': {'dev': dev, 'ino': 1}, '/mnt/stack': {'dev': dev, 'ino': 2}}).start()
        self.real_permissions = h.Anchors.permissions
        def permissions(a, path, fd):
            s = os.fstat(fd)
            self.inode_paths[s.st_dev, s.st_ino] = path
            if not path.is_relative_to(self.base):
                return self.fake_fact(fd)  # No host ancestor facts beyond fstat.
            return self.real_permissions(a, path, fd)
        patch.object(h.Anchors, 'permissions', new=permissions).start()
        patch.object(h, 'fact', side_effect=self.fake_fact).start()
        # No subprocess/host procfs in canonical ACL checking: only source API.
        patch.object(h.load('project-domain-runtime'), 'OWNER', os.getuid()).start()

    def fake_fact(self, fd):
        s = os.fstat(fd)
        path = self.inode_paths[s.st_dev, s.st_ino]
        row = dict(dev=s.st_dev, ino=s.st_ino, uid=s.st_uid, gid=s.st_gid,
                   mode=stat.S_IMODE(s.st_mode), acl='', defaultAcl='',
                   mountId=2 if path.is_relative_to(self.scope) else 1)
        row.update(self.fact_overrides.get(path, {}))
        return row

    def mountinfo(self, root_opts='rw,relatime', super_opts='rw', extra=''):
        return (f'1 0 {self.device} / / {root_opts} - ext4 /dev/root {super_opts}\n'
                f'2 1 {self.device} / /mnt/stack rw,relatime - ext4 /dev/stack rw\n' + extra).encode()

    def put(self, path, body):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(body)
        path.chmod(0o600)

    def reseal(self):
        self.put(self.bundle / 'stack.ir.json', h.encoded(self.ir))
        self.receipt = dict(schemaVersion=1, release=str(self.bundle), phase='preparing',
                            steps=['preparing'], inputs={name: h.sha((self.bundle / name).read_bytes()) for name in h.REQUIRED})
        self.save_receipt()

    def save_receipt(self):
        self.put(self.bundle / 'installation-receipt.json', h.encoded(self.receipt))
        self.put(self.install / '.install-intent.json', h.encoded(self.receipt))

    def assert_refused(self, call=None):
        with self.assertRaises((ValueError, OSError, KeyError, TypeError)):
            (call or (lambda: h.prepare(self.bundle)))()

    def test_prepare_validate_no_marker_content_and_exact_separate_private_proof(self):
        proof = h.prepare(self.bundle)
        self.assertEqual(proof, h.validate(self.bundle, proof))
        self.assertEqual(proof, h.validate(self.bundle, proof['proofSha256']))
        self.assertEqual(proof, h.prepare(self.bundle))
        self.assertEqual(['mnt'], os.listdir(self.root))
        self.assertEqual(['stack'], os.listdir(self.root / 'mnt'))
        self.assertEqual([], os.listdir(self.root / 'mnt/stack'))
        self.assertEqual([], os.listdir(self.stack))
        self.assertEqual(0o600, stat.S_IMODE((self.bundle / h.PROOF).stat().st_mode))
        self.assertEqual(1, (self.bundle / h.PROOF).stat().st_nlink)
        self.assertEqual(proof, h.strict((self.bundle / h.PROOF).read_bytes()))
        self.assertEqual(proof['authority']['scopeMarkerSha256'], h.sha((self.scope / '.stack-installation.json').read_bytes()))
        self.assertEqual(proof['proofSha256'], h.sha(h.encoded({k: v for k, v in proof.items() if k != 'proofSha256'})))

    def test_validate_across_exact_canonical_journal_phases(self):
        proof = h.prepare(self.bundle)
        for index, phase in enumerate(h.PHASES[1:], 1):
            self.receipt.update(phase=phase, steps=list(h.PHASES[:index + 1]),
                                readiness={'hostMetricsViews': proof})
            self.save_receipt()
            self.assertEqual(proof, h.validate(self.bundle, proof))
        self.receipt.update(phase='failed', steps=['preparing', 'failed'])
        self.save_receipt()
        self.assert_refused(lambda: h.validate(self.bundle, proof))

    def test_does_not_adopt_existing_empty_root_or_stack_view(self):
        for target in (self.root, self.stack):
            target.mkdir(mode=0o755)
            self.assert_refused()
            self.assertFalse((self.bundle / h.PROOF).exists())
            target.rmdir()  # Test-owned empty directory only.

    def test_foreign_files_symlinks_hardlinks_and_specials_fail_without_repair(self):
        proof = h.prepare(self.bundle)
        for target in (self.root, self.root / 'mnt', self.root / 'mnt/stack', self.stack):
            foreign = target / 'foreign'
            self.put(foreign, b'fixture data must survive\n')
            self.assert_refused(lambda: h.validate(self.bundle, proof))
            self.assertEqual(b'fixture data must survive\n', foreign.read_bytes())
            foreign.unlink()
        linked = self.stack / 'linked'
        linked.symlink_to(self.root)
        self.assert_refused(lambda: h.validate(self.bundle, proof))
        linked.unlink()
        os.link(self.scope / '.stack-installation.json', linked)
        self.assert_refused(lambda: h.validate(self.bundle, proof))
        linked.unlink()
        os.mkfifo(linked)
        self.assert_refused(lambda: h.validate(self.bundle, proof))
        linked.unlink()

    def test_linked_ancestor_or_view_is_not_followed(self):
        proof = h.prepare(self.bundle)
        held = self.root.with_name('held')
        self.root.rename(held)
        self.root.symlink_to(held, target_is_directory=True)
        self.assert_refused(lambda: h.validate(self.bundle, proof))
        self.assertEqual([], os.listdir(held / 'mnt/stack'))

    def test_symlinked_and_hardlinked_proof_rejected(self):
        proof = h.prepare(self.bundle)
        record = self.bundle / h.PROOF
        os.link(record, self.bundle / 'proof-alias')
        self.assert_refused(lambda: h.validate(self.bundle, proof))
        (self.bundle / 'proof-alias').unlink()
        record.rename(self.bundle / 'proof-held')
        record.symlink_to('proof-held')
        self.assert_refused(lambda: h.validate(self.bundle, proof))

    def test_device_and_mount_mismatch_fail_before_any_view_creation(self):
        for path, overrides in ((self.root.parent, {'dev': 12345}),
                                (self.stack.parent, {'dev': 12345})):
            self.fact_overrides[path] = overrides
            self.assert_refused()
            self.assertFalse(self.root.exists())
            self.assertFalse(self.stack.exists())
            self.fact_overrides.clear()

    def test_parent_bind_alias_and_native_stat_mismatch_fail_before_creation(self):
        self.fact_overrides[self.root.parent] = {'mountId': 55}
        self.assert_refused()
        self.assertFalse(self.root.exists())
        self.fact_overrides.clear()
        with patch.object(h, 'host_devices', return_value={
                '/': {'dev': 12345, 'ino': 1}, '/mnt/stack': {'dev': 12345, 'ino': 2}}):
            self.assert_refused()
        self.assertFalse(self.root.exists())

    def test_same_device_bind_alias_and_nested_submount_rejected(self):
        proof = h.prepare(self.bundle)
        self.fact_overrides[self.root / 'mnt/stack'] = {'mountId': 55}
        self.assert_refused(lambda: h.validate(self.bundle, proof))
        self.fact_overrides.clear()
        self.native = self.mountinfo(extra=f'55 2 {self.device} / {self.stack}/sub rw - ext4 /dev/stack rw\n')
        self.assert_refused(lambda: h.validate(self.bundle, proof))

    def test_scope_ancestor_replacement_even_with_same_marker_and_leaf_inodes_fails(self):
        proof = h.prepare(self.bundle)
        held = self.scope.with_name('scope-held')
        self.scope.rename(held)
        self.scope.mkdir(mode=0o700)
        (held / 'volumes').rename(self.scope / 'volumes')
        (held / '.stack-installation.json').rename(self.scope / '.stack-installation.json')
        self.assert_refused(lambda: h.validate(self.bundle, proof))

    def test_foreign_mode_owner_acl_or_default_acl_never_repaired(self):
        proof = h.prepare(self.bundle)
        for override in ({'uid': os.getuid() + 100}, {'mode': 0o777},
                         {'acl': 'deadbeef'}, {'defaultAcl': 'deadbeef'}):
            self.fact_overrides[self.stack] = override
            self.assert_refused(lambda: h.validate(self.bundle, proof))
            self.assertEqual(override, self.fact_overrides[self.stack])
        self.fact_overrides.clear()

    def test_exact_descriptor_ir_scope_marker_receipt_unit_and_cas_pins(self):
        proof = h.prepare(self.bundle)
        paths = [self.bundle / 'stack.config' / h.DESCRIPTOR,
                 self.bundle / 'runtime/configs' / h.DESCRIPTOR,
                 self.bundle / 'stack.ir.json', self.scope / '.stack-installation.json',
                 self.bundle / 'installation-receipt.json', self.unit]
        for path in paths:
            original = path.read_bytes()
            self.put(path, original + b' ')
            self.assert_refused(lambda: h.validate(self.bundle, proof))
            self.put(path, original)
        wrong = copy.deepcopy(proof)
        wrong['authority']['selectedScope'] = str(self.base / 'foreign')
        self.assert_refused(lambda: h.validate(self.bundle, wrong))
        self.put(self.install / '.install-intent.json', b'{}\n')
        self.assert_refused(lambda: h.validate(self.bundle, proof))

    def test_duplicate_json_and_input_path_escape_rejected(self):
        self.put(self.bundle / 'installation-receipt.json', b'{"schemaVersion":1,"schemaVersion":1}')
        self.assert_refused()
        self.reseal()
        self.receipt['inputs']['../outside'] = '0' * 64
        self.save_receipt()
        self.assert_refused()
        self.assertFalse(self.root.exists())

    def test_unselected_service_privilege_regression_extra_mount_and_alias_consumer(self):
        for key, value in (('pidMode', 'private'), ('user', '0:0'), ('privileged', True),
                           ('capAdd', ['SYS_ADMIN']), ('volumes', h.MOUNTS + ['/:/bad:ro'])):
            original = copy.deepcopy(self.ir)
            self.ir['services']['node-exporter'][key] = value
            self.reseal()
            self.assert_refused()
            self.ir = original
        self.ir['volumes']['alias'] = {'hostPath': str(self.stack.parent)}
        self.ir['services']['other'] = {'volumes': ['alias:/bad:ro']}
        self.reseal()
        self.assert_refused()
        self.assertFalse(self.root.exists())
        self.ir['services'].pop('node-exporter')
        self.reseal()
        self.assert_refused()

    def test_quadlet_omission_broad_mount_extra_engine_args_and_wrong_scope_rejected(self):
        original = self.unit.read_bytes()
        for wrong in (original.replace(b' --pid=host', b''),
                      original.replace(b' --pid=host', b' --pid=private'),
                      original + b'Pid=host\n',
                      original.replace(b'User=65534:65534', b'User=0:0'),
                      original.replace(b'PodmanArgs=--image-volume=ignore', b'PodmanArgs=--privileged'),
                      original + b'Volume=/:/host:ro\n',
                      original + b'[Service]\nExecStart=/bin/false\n',
                      original + b'[Service]\nEnvironment=CONTAINERS_CONF=/foreign\n',
                      original.replace(str(self.stack).encode(), ('/wrong/' + h.VOLUME).encode()),
                      original.replace(b'NoNewPrivileges=true', b'AddCapability=SYS_ADMIN')):
            self.put(self.unit, wrong)
            self.assert_refused()
        self.assertFalse(self.root.exists())

    def test_source_bound_resource_flags_and_host_pid_namespace_match_real_generator_shape(self):
        text = self.unit.read_text()
        limits = {'memory': '2G', 'cpus': '2.0'}
        rendered = text.replace('--image-volume=ignore --pid=host',
                                '--image-volume=ignore --memory=2G --cpus=2.0 --pid=host')
        self.assertEqual(h.check_unit(rendered, self.install, limits), str(self.stack))
        for wrong in (rendered.replace('--memory=2G', '--memory=1G'),
                      rendered.replace('--cpus=2.0', '--cpus=1.0'),
                      rendered.replace('--pid=host', '--pid=private'),
                      rendered.replace('--pid=host', '--pid=host --pid=private')):
            with self.assertRaises(ValueError): h.check_unit(wrong, self.install, limits)
        with self.assertRaises(ValueError): h.check_unit(rendered, self.install)
        self.assertEqual(h.resource_arguments({'memory': '${MEM:-2g}', 'cpus': '${CPU:-2.0}'}),
                         ['--memory=2G', '--cpus=2.0'])
        for limits in ({'memory': '0G'}, {'memory': '2G --privileged'}, {'cpus': '0'},
                       {'cpus': 'NaN'}, {'memory': '${MEM}'}, []):
            with self.assertRaises(ValueError): h.resource_arguments(limits)

    def test_readonly_native_host_supported_or_fail_closed_never_bind_ro_substitution(self):
        self.native = self.mountinfo(root_opts='ro,relatime', super_opts='ro,errors=remount-ro')
        self.assert_refused()
        self.assertFalse(self.root.exists())
        self.native = self.mountinfo(root_opts='ro', super_opts='rw')
        proof = h.prepare(self.bundle)
        self.assertIn('ro', proof['nativeMounts']['/']['options'])

    def test_root_and_stack_namespace_mountinfo_must_match(self):
        with patch.object(h, 'mounts', return_value=(self.native, self.native.replace(b'/dev/root', b'/dev/other'))):
            self.assert_refused()
        self.assertFalse(self.root.exists())

    def test_retained_fd_rewalk_detects_renamed_parent(self):
        proof = h.prepare(self.bundle)
        real_verify = h.Anchors.verify
        def swap(a, records):
            self.stack.rename(self.stack.with_name('held'))
            self.stack.mkdir(mode=0o755)
            real_verify(a, records)
        with patch.object(h.Anchors, 'verify', new=swap):
            self.assert_refused(lambda: h.validate(self.bundle, proof))

    def test_operator_2770_stack_group_actor_execute_acl_is_accepted(self):
        # Reuse the canonical ACL/account-role validator with no host account IO.
        actor = 24001
        entries = [(1, 7, 0xffffffff), (2, 1, actor), (4, 7, 0xffffffff),
                   (16, 7, 0xffffffff), (32, 0, 0xffffffff)]
        acl = (struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *r) for r in entries)).hex()
        roles = {self.scope: (1234, os.getgid(), {actor}),
                 self.stack.parent: (1234, os.getgid(), {actor})}
        self.fact_overrides[self.scope] = dict(uid=1234, mode=0o2770, acl=acl)
        self.fact_overrides[self.stack.parent] = dict(uid=1234, mode=0o2770, acl=acl)
        self.roles_mock.return_value = self.scope, self.marker, roles
        proof = h.prepare(self.bundle)
        self.assertEqual(proof, h.validate(self.bundle, proof))
        bad = acl[:-16] + struct.pack('<HHI', 32, 1, 0xffffffff).hex()
        self.fact_overrides[self.scope]['acl'] = bad
        self.assert_refused(lambda: h.validate(self.bundle, proof))


class RoleAuthority(unittest.TestCase):
    def test_canonical_marker_account_and_stack_group_are_reused(self):
        with tempfile.TemporaryDirectory(prefix='metrics-role-test-') as name:
            scope = Path(name) / 'scope'
            (scope / 'volumes').mkdir(parents=True)
            scope.chmod(0o2770)
            (scope / 'volumes').chmod(0o2770)
            operator = SimpleNamespace(pw_uid=1234, pw_gid=1235, pw_name='fixture')
            marker = {'domains': [{'uid': 24001}, {'uid': 24002}]}
            storage = SimpleNamespace(authority=lambda bundle: (scope, operator, marker))
            group = SimpleNamespace(gr_gid=2345, gr_mem=['fixture'])
            with patch.object(h, 'load', return_value=storage), patch.object(h.grp, 'getgrnam', return_value=group) as lookup:
                found, expected, roles = h.role_authority(Path(name) / 'bundle')
                self.assertEqual(scope, found)
                self.assertEqual(marker, expected)
                self.assertEqual((1234, 2345, {24001, 24002}), roles[scope])
                lookup.assert_called_once_with('stack')
                group.gr_mem = ['foreign']
                with self.assertRaises(ValueError):
                    h.role_authority(Path(name) / 'bundle')


class Snapshot(unittest.TestCase):
    def fixture(self):
        body = b'1 0 8:1 / / rw,relatime - ext4 /dev/root rw\n2 1 8:2 / /mnt/stack rw - ext4 /dev/stack rw\n'
        devices = {'/': {'dev': os.makedev(8, 1), 'ino': 1}, '/mnt/stack': {'dev': os.makedev(8, 2), 'ino': 2}}
        vfs = SimpleNamespace(f_flag=0, f_blocks=10000, f_frsize=4096,
                              f_bfree=9000, f_bavail=8000, f_files=1000, f_ffree=900)
        return body, devices, vfs

    def test_runtime_snapshot_contract_without_any_host_reads(self):
        body, devices, vfs = self.fixture()
        def text(path, *args, **kwargs):
            values = {'/proc/meminfo': 'MemTotal: 12345 kB\n',
                      '/proc/stat': 'cpu 100 2 3 4 5 6 7 8\ncpu0 100 2 3 4 5 6 7 8 9 10\n'}
            return values[str(path)]
        with patch.object(h, 'host_devices', return_value=devices), patch.object(h.Path, 'read_bytes', return_value=body), \
             patch.object(h.Path, 'read_text', new=text), patch.object(h.os, 'statvfs', return_value=vfs), \
             patch.object(h.os, 'sysconf', return_value=100):
            result = h.snapshot()
            self.assertEqual(12345 * 1024, result['memTotalBytes'])
            self.assertEqual(1., result['cpus']['0']['user'])
            self.assertEqual(10000 * 4096, result['filesystems']['/']['size_bytes'])
            self.assertEqual(0, result['filesystems']['/']['readonly'])
            vfs.f_flag = os.ST_RDONLY
            with self.assertRaises(ValueError):
                h.snapshot()


class Metrics(unittest.TestCase):
    def setUp(self):
        self.before = dict(start=1., end=1.1, mountinfoSha256='fixture', memTotalBytes=12345678,
                           nativeDevices={'/': {'dev': 1, 'ino': 1}, '/mnt/stack': {'dev': 2, 'ino': 2}},
                           cpus={'0': {mode: 100. for mode in ('user', 'nice', 'system', 'idle', 'iowait', 'irq', 'softirq', 'steal')}},
                           filesystems={p: dict(device='/dev/' + name, fstype='ext4', major='8', minor=minor,
                             size_bytes=1024**3, free_bytes=800000000, avail_bytes=700000000,
                             files=100000, files_free=50000, readonly=0, device_error=0)
                             for p, name, minor in (('/', 'root', '1'), ('/mnt/stack', 'stack', '2'))})
        self.after = copy.deepcopy(self.before)
        self.after.update(start=1.2, end=1.3)
        self.metrics = []
        for path, row in self.before['filesystems'].items():
            labels = dict(device=row['device'], fstype=row['fstype'], mountpoint=path, device_error='')
            for suffix in h.FS_METRICS:
                self.emit('node_filesystem_' + suffix, labels, row[suffix])
            self.emit('node_filesystem_mount_info', dict(device=row['device'], major='8', minor=row['minor'], mountpoint=path), 1)
            self.emit('node_filesystem_purgeable_bytes', labels, 0)
        self.emit('node_memory_MemTotal_bytes', {}, self.before['memTotalBytes'])
        for mode in self.before['cpus']['0']:
            self.emit('node_cpu_seconds_total', dict(cpu='0', mode=mode), 100)

    def emit(self, name, labels, value):
        suffix = '{' + ','.join(k + '=' + json.dumps(v) for k, v in labels.items()) + '}' if labels else ''
        self.metrics.append(name + suffix + ' ' + str(value))

    def compare(self, metrics=None, before=None, after=None):
        return h.compare_metrics('\n'.join(metrics or self.metrics), before or self.before, after or self.after)

    def test_exact_projected_labels_counters_inodes_and_host_readonly(self):
        result = self.compare()
        self.assertTrue(result['checked'])
        self.assertEqual(1, result['cpuCount'])
        self.assertNotIn('accepted', result)

    def test_counter_label_device_readonly_error_and_inode_substitution_fail(self):
        for old, new in [('readonly{', 'unexpected{'), (' 12345678', ' 1000'),
                         (' 100', ' 1'), ('/dev/root', 'overlay'), ('mountpoint="/"', 'mountpoint="/host"'),
                         ('device_error=""', 'device_error="bad"'), (' 100000', ' 10'),
                         (' 800000000', ' 1')]:
            metrics = [line.replace(old, new) for line in self.metrics]
            with self.subTest(old=old), self.assertRaises(ValueError):
                self.compare(metrics)
        metrics = [line.rsplit(' ', 1)[0] + ' 1' if line.startswith('node_filesystem_readonly') else line for line in self.metrics]
        with self.assertRaises(ValueError):
            self.compare(metrics)

    def test_missing_extra_duplicate_nonfinite_and_projected_prometheus_labels_fail(self):
        extras = [self.metrics + [self.metrics[0]], self.metrics[1:],
                  [line.replace('cpu="0"', 'cpu="1"') for line in self.metrics],
                  [line.replace(' 100000', ' NaN') for line in self.metrics],
                  self.metrics + ['node_filesystem_bad{mountpoint="/private"} 0']]
        for rows in extras:
            with self.assertRaises(ValueError):
                self.compare(rows)

    def test_bounded_window_mount_identity_dynamic_byte_and_inode_drift(self):
        after = copy.deepcopy(self.after)
        after['end'] = 12
        with self.assertRaises(ValueError):
            self.compare(after=after)
        after = copy.deepcopy(self.after)
        after['mountinfoSha256'] = 'changed'
        with self.assertRaises(ValueError):
            self.compare(after=after)
        rows = [line.replace(' 800000000', ' 799999000').replace(' 50000', ' 49999') for line in self.metrics]
        self.assertTrue(self.compare(rows)['checked'])


if __name__ == '__main__':
    unittest.main()
