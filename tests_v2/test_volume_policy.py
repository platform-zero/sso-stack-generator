"""Pure policy and actual nonexecuting native translation, not volume effects."""
import copy
from pathlib import Path
import subprocess
import tempfile
import unittest

from p0core.model import Catalog, ContractError
from p0core.render import render
from p0core.volumes import declared_custodies, definition, digest, VolumeError
from p0core.volumecontext import _mount_identity

IMAGE = 'docker.io/library/alpine@sha256:' + 'a' * 64
POLICY = {'uid': 1000, 'gid': 1000, 'mode': '0700'}


def service(name='app', runtime='rootless', **mount):
    return {'id': name, 'runtime': runtime, 'image': IMAGE, 'requires': [],
            'mounts': [dict(kind='volume', source='data', target='/data', **mount)]}


def catalog(*services):
    return Catalog([{'schemaVersion': 1, 'id': 'apps', 'services': list(services)}])


class VolumePolicyTests(unittest.TestCase):
    def test_shared_policy_snapshot_and_distinct_runtime_stores(self):
        first = service(custody=copy.deepcopy(POLICY))
        graph = catalog(first, service('other', custody=POLICY), service('edge', 'rootful'))
        first['mounts'][0]['custody']['uid'] = 0
        specs = [entry.declaration for entry in graph.services.values()]
        self.assertEqual(declared_custodies(specs), {'data': POLICY})

    def test_mixed_or_changed_shared_custody_rejected_before_render(self):
        for second in (service('other'), service('other', custody=dict(POLICY, uid=0)),
                       service('other', custody=dict(POLICY, mode='0750'))):
            with self.subTest(second=second), self.assertRaisesRegex(ContractError, 'shared-custody-conflict'):
                catalog(service(custody=POLICY), second)

    def test_bad_policy_and_wrong_kind_or_runtime_refused(self):
        bad = [None, {}, dict(POLICY, uid=True), dict(POLICY, uid=1000.0),
               dict(POLICY, gid=-1), dict(POLICY, gid=65536), dict(POLICY, mode='0777'),
               dict(POLICY, path='/tmp/foreign')]
        for policy in bad:
            with self.subTest(policy=policy), self.assertRaises(ContractError):
                catalog(service(custody=policy))
        for runtime in ('rootful', 'test'):
            with self.subTest(runtime=runtime), self.assertRaises(ContractError):
                catalog(service(runtime=runtime, custody=POLICY))
        wrong = service(custody=POLICY)
        wrong['mounts'][0]['kind'] = 'secret'
        with self.assertRaises(ContractError):
            catalog(wrong)

    def test_render_nocopy_semantic_labels_never_uid_options_or_recursive_chown(self):
        for readonly, suffix in ((False, ':nocopy'), (True, ':ro,nocopy')):
            _, files = render(catalog(service(custody=POLICY, readOnly=readonly)), ['app'])
            self.assertIn('Volume=p0-data.volume:/data' + suffix, files['quadlet/rootless/p0-app.container'])
            body = files['quadlet/rootless/p0-data.volume']
            self.assertIn('Label=io.platform-zero.volume.intent=' + digest(definition('data', POLICY)), body)
            self.assertNotIn('Options=', body)
            self.assertNotIn(':U', ''.join(files.values()))
        _, bare = render(catalog(service()), ['app'])
        self.assertIn('Volume=p0-data.volume:/data\n', bare['quadlet/rootless/p0-app.container'])
        self.assertNotIn('volume.intent', bare['quadlet/rootless/p0-data.volume'])

    @unittest.skipUnless(Path('/usr/libexec/podman/quadlet').is_file(), 'native Quadlet unavailable')
    def test_native_translation_keeps_nocopy_and_existing_volume_ignore(self):
        _, files = render(catalog(service(custody=POLICY)), ['app'])
        with tempfile.TemporaryDirectory(prefix='p0-volume-render-') as directory:
            root = Path(directory)
            for name, body in files.items():
                (root / Path(name).name).write_text(body)
            result = subprocess.run(['/usr/libexec/podman/quadlet', '-dryrun', '-no-kmsg-log'],
                                    cwd=root, env={'PATH': '/usr/bin:/bin', 'QUADLET_UNIT_DIRS': str(root)},
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    text=True, timeout=15)
            self.assertEqual(result.returncode, 0)
            self.assertIn('p0-data:/data:nocopy', result.stdout)
            creates = [line for line in result.stdout.splitlines() if line.startswith('ExecStart=')
                       and 'volume create' in line]
            self.assertEqual(len(creates), 1)
            self.assertIn('--ignore', creates[0])
            self.assertIn('io.platform-zero.volume.intent=', creates[0])

    def test_kernel_private_mount_identity_is_exact_not_ancestor_or_shared(self):
        raw = b'41 25 8:1 /p0-v2 /mnt/stack/p0-v2 rw - ext4 /dev/example rw\n'
        self.assertEqual(_mount_identity(raw, 41)['target'], '/mnt/stack/p0-v2')
        for bad, identity in ((raw, 42), (raw + raw, 41),
                              (raw.replace(b'rw -', b'rw shared:5 -'), 41),
                              (raw.replace(b'/mnt/stack/p0-v2', b'/mnt/stack'), 41),
                              (raw.replace(b'rw -', b'rw unbindable -'), 41)):
            with self.subTest(bad=bad, identity=identity), self.assertRaises(VolumeError):
                _mount_identity(bad, identity)


if __name__ == '__main__':
    unittest.main()
