#!/usr/bin/env python3
"""Source/model-only ownership regressions. Never mount/load policy/run engine."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

OPS = Path(__file__).parents[1] / 'runtime-generator/podman-ops'
spec = importlib.util.spec_from_file_location('root_store_model', OPS / 'native-rootful-store.py')
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)
ispec = importlib.util.spec_from_file_location('root_store_image_model', OPS / 'install-pinned-images.py')
i = importlib.util.module_from_spec(ispec); ispec.loader.exec_module(i)


def metadata():
    state, scope = '/var/lib/stack-model', '/mnt/stack/model'
    return dict(deploymentMode='standalone', installerStateRoot=state,
        storageScope=dict(root=scope, dataClass='synthetic'),
        domains=[dict(stateRoot=scope + '/platform', graphRoot=scope + '/platform/storage',
                      volumeRoot=scope + '/volumes/platform')],
        rootfulStore=dict(schemaVersion=1, kind='standalone-owned-rootful-store',
            scopeRoot=scope, scopeMarkerSha256='a' * 64, stateRoot=state + '/rootful-store',
            dataRoot=state + '/rootful-store/graph', graphRoot=state + '/rootful-store/graph',
            runRoot='/run/stack-model-podman', networkRoot=state + '/rootful-store/networks'))


def owner():
    result = s.Store.__new__(s.Store)
    result.metadata = metadata(); result.value = s.definition(result.metadata)
    result.context_sha = s.digest(s.canonical(result.value))
    result.bundle = Path('/var/lib/stack-model/candidate')
    result.opened = []; result.pointer = None
    result.reserve = mock.Mock()
    return result


class Models(unittest.TestCase):
    def test_legacy_absence_only_not_null_or_empty_profile(self):
        self.assertIsNone(s.definition({}))
        for value in (None, {}, False, '', []):
            with self.subTest(value=value), self.assertRaises(ValueError):
                s.definition(dict(metadata(), rootfulStore=value))

    def test_closed_schema_and_exact_private_graph(self):
        m = metadata(); self.assertEqual(s.definition(m), m['rootfulStore'])
        changes = dict(schemaVersion=True, kind='p0test-context', scopeRoot='/mnt/stack/foreign',
            scopeMarkerSha256='not-a-hash', stateRoot='/var/lib/containers',
            dataRoot='/mnt/stack/model/platform/storage', graphRoot='/var/lib/containers/storage',
            runRoot='/run/containers/storage', networkRoot='/etc/containers/networks', extra='value')
        for key, value in changes.items():
            candidate = copy.deepcopy(m); candidate['rootfulStore'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                s.definition(candidate)

    def test_not_a_venue_or_non_native_redirect(self):
        for extra in ({'venue': {}}, {'deploymentMode': 'distribution'},
                      {'storageScope': {'root': '/mnt/stack/model', 'dataClass': 'unknown'}}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                s.definition(dict(metadata(), **extra))

    def test_actor_and_root_data_authorities_disjoint(self):
        for field in ('stateRoot', 'graphRoot', 'volumeRoot'):
            for overlap in ('/var/lib/stack-model/rootful-store', '/var/lib/stack-model/rootful-store/graph/nested', '/var/lib/stack-model'):
                m = metadata(); m['domains'][0][field] = overlap
                with self.subTest(field=field, overlap=overlap), self.assertRaises(ValueError):
                    s.definition(m)

    def test_config_and_every_engine_prefix_pin_all_three_roots(self):
        o = owner(); o.verify = mock.Mock(return_value={})
        prefix = o.command(); o.verify.assert_called_once()
        self.assertNotEqual(prefix, ['podman'])
        for option, key in (('--root', 'graphRoot'), ('--runroot', 'runRoot'), ('--network-config-dir', 'networkRoot')):
            self.assertEqual(prefix[prefix.index(option) + 1], o.value[key])
        self.assertIn('CONTAINERS_STORAGE_CONF=' + o.value['stateRoot'] + '/containers-storage.conf', prefix)
        self.assertIn('CONTAINERS_CONF=' + o.value['stateRoot'] + '/containers.conf', prefix)
        configs = s.config_bytes(o.value)
        self.assertIn(o.value['graphRoot'].encode(), configs['containers-storage.conf'])
        self.assertIn(o.value['runRoot'].encode(), configs['containers-storage.conf'])
        self.assertIn(o.value['networkRoot'].encode(), configs['containers.conf'])
        self.assertNotIn(b'/var/lib/containers/storage', b''.join(configs.values()))

    def test_image_owner_routes_native_context_and_closes_on_refusal(self):
        for refuse in (False, True):
            selected = mock.Mock()
            selected.command.side_effect = ValueError('model custody refusal') if refuse else None
            selected.command.return_value = ['model-private-context', '/usr/bin/podman']
            factory = mock.Mock(return_value=selected)
            with mock.patch.object(i, 'read_json', return_value=metadata()), \
                 mock.patch.object(i, 'native_store_owner', return_value=types.SimpleNamespace(Store=factory)):
                if refuse:
                    with self.assertRaises(ValueError): i.rootful_command(Path('/source-model'))
                else:
                    self.assertEqual(i.rootful_command(Path('/source-model')), selected.command.return_value)
                selected.close.assert_called_once()
                factory.assert_called_once_with(Path('/source-model'))

    def test_failed_custody_never_falls_back_to_default_engine(self):
        o = owner(); o.verify = mock.Mock(side_effect=ValueError('model refusal'))
        with self.assertRaises(ValueError): o.command()

    def test_ordinary_directory_link_is_not_a_mount_or_control_authority(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw); (base / 'real').mkdir(); (base / 'alias').symlink_to('real')
            with self.assertRaises(OSError): s.directory(base / 'alias')

    def test_operator_source_rejected_without_leaking_descriptors(self):
        if os.geteuid() == 0: self.skipTest('negative test expects unprivileged caller')
        before = len(list(Path('/proc/self/fd').iterdir()))
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(ValueError): s.Store(raw)
        self.assertEqual(before, len(list(Path('/proc/self/fd').iterdir())))

    def test_read_pin_ignores_atime_but_not_mutation_or_identity(self):
        with tempfile.TemporaryFile() as stream:
            stream.write(b'public model'); stream.flush(); before = os.fstat(stream.fileno())
            stream.seek(0); stream.read(); after = os.fstat(stream.fileno())
            self.assertEqual(s.file_pin(before), s.file_pin(after))
            stream.write(b'x'); stream.flush()
            self.assertNotEqual(s.file_pin(before), s.file_pin(os.fstat(stream.fileno())))

    def test_image_records_are_closed_source_data_not_commands_or_permissions(self):
        context = 'a' * 64
        record = dict(schemaVersion=1, contextSha256=context, images={'b' * 64: [
            dict(kind='qualified-local-archive', proofSha256='c' * 64, sourceMetadataSha256='d' * 64)]})
        self.assertEqual(s.imports_document(s.canonical(record), context), record)
        for extra in ({'permit': True}, {'schemaVersion': True}, {'contextSha256': 'e' * 64},
                      {'images': {'not-an-id': []}}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                s.imports_document(s.canonical(dict(record, **extra)), context)

    def test_private_read_rejects_operator_inode_before_reading(self):
        if os.geteuid() == 0: self.skipTest('negative test expects unprivileged caller')
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw); (base / 'control').write_bytes(b'public model')
            fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(os, 'read') as read, self.assertRaises(ValueError):
                    s.read_at(fd, 'control')
                read.assert_not_called()
            finally: os.close(fd)

    def test_prepare_parent_marker_mismatch_refuses_before_any_new_inode(self):
        o = owner(); storage = mock.Mock()
        storage.authority.return_value = (Path(o.value['scopeRoot']), 1000, {'model': 'different-marker'})
        with mock.patch.object(s, 'lock_held'), mock.patch.object(os, 'geteuid', return_value=0), \
             mock.patch.object(os, 'mkdir') as mkdir, mock.patch.object(s.subprocess, 'run') as run:
            with self.assertRaises(ValueError): o.prepare(storage)
            mkdir.assert_not_called(); run.assert_not_called()

    def test_existing_partial_control_is_not_repaired_adopted_or_mounted(self):
        o = owner(); expected = {'model': 'source-marker'}
        o.value['scopeMarkerSha256'] = hashlib.sha256((json.dumps(expected, sort_keys=True) + '\n').encode()).hexdigest()
        storage = mock.Mock(); storage.authority.return_value = (Path(o.value['scopeRoot']), 1000, expected)
        o.verify = mock.Mock(side_effect=ValueError('incomplete creation custody'))
        with mock.patch.object(s, 'lock_held'), mock.patch.object(os, 'geteuid', return_value=0), \
             mock.patch.object(Path, 'exists', return_value=True), mock.patch.object(os, 'mkdir') as mkdir, \
             mock.patch.object(s.subprocess, 'run') as run:
            with self.assertRaises(ValueError): o.prepare(storage)
            o.verify.assert_called_once(); mkdir.assert_not_called(); run.assert_not_called()

    def test_staging_or_historical_identity_not_runtime_admission(self):
        o = owner(); o.verify = mock.Mock(return_value={'phase': 'ready-image-only'})
        with mock.patch.object(s, 'lock_held'), mock.patch.object(s, 'replace_at') as replace:
            with self.assertRaises(ValueError): o.admit_runtime()
            replace.assert_not_called()

    def test_historical_runtime_custody_not_replayed_as_admission(self):
        o = owner(); o.verify = mock.Mock(return_value={'phase': 'runtime-admitted'})
        with mock.patch.object(s, 'lock_held'), mock.patch.object(s, 'replace_at') as replace:
            with self.assertRaises(ValueError): o.admit_runtime()
            replace.assert_not_called()

    def test_runtime_startup_cannot_use_image_only_custody(self):
        o = owner(); o.verify = mock.Mock(return_value={'phase': 'ready-image-only'})
        with mock.patch.object(s, 'directory') as directory:
            with self.assertRaises(ValueError): o.runtime_selected()
            directory.assert_not_called()

    def test_library_does_not_load_policy_or_enter_a_host_namespace(self):
        body = (OPS / 'native-rootful-store.py').read_text()
        for forbidden in ('apparmor_parser', 'nsenter', '--pid=host', 'CAP_SYS_ADMIN', '--privileged', 'image prune'):
            self.assertNotIn(forbidden, body)
        self.assertNotIn('subprocess.run(', body)
        self.assertNotIn('os.unshare(', body)
        self.assertNotIn("'/usr/bin/mount'", body)
        self.assertNotIn("if __name__ ==", body)


if __name__ == '__main__':
    unittest.main()
