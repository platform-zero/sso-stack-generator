#!/usr/bin/env python3
"""Isolated/mock source proof ONLY; no native/kernel/container/network calls."""
import copy
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('owner_under_test', BASE / 'runtime-generator/podman-ops/native-readiness-owner.py')
o = importlib.util.module_from_spec(spec); spec.loader.exec_module(o)
# Reuse the existing readiness stream's SYNTHETIC fixtures, never its live CLI.
spec = importlib.util.spec_from_file_location('graph_fixtures', BASE / 'scripts/test-native-readiness.py')
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
ROOT = Path('/sealed'); RELEASE = ROOT / 'releases/r1'
BOOT = '12345678-1234-1234-1234-123456789abc'
IMAGE = 'sha256:' + 'a' * 64


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def fixture():
    ir, domains, rendered = f.fixture()
    ir['quadletBuildImagesFrozen'] = True
    for i, row in enumerate(domains['domains']):
        row['uid'] = 780 + i
        for key in ('stateRoot', 'graphRoot', 'volumeRoot'):
            row[key] = '/scope/' + row['name'] + '/' + key
    for service in ir['services'].values(): service['updatePolicy'] = 'pinned'
    for name in list(rendered):
        if name.endswith('.build'):
            rendered[name] = b'[Build]\nImageTag=localhost/webservices/app:bundle\n'
    bodies = {'stack.ir.json': encoded(ir), 'podman-domains.json': encoded(domains),
              'bundle.json': b'{}', 'source-provenance.json': b'{}',
              'site/manifest.json': encoded({'deploymentMode': 'standalone', 'installerStateRoot': str(ROOT),
                                            'storageScope': domains['storageScope']})}
    pins = {name: o.r.sha(bodies[name]) if name in bodies else None
            for name in o.journal.CORE_INPUTS + o.journal.PINNED_INPUTS}
    intent = {'schemaVersion': 1, 'release': str(RELEASE), 'phase': 'preparing',
              'steps': ['preparing'], 'inputs': pins}
    storage = {'scope': '/scope', 'markerSha256': 'b' * 64, 'authority': {}, 'custody': {}}
    return ir, domains, rendered, bodies, intent, storage


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.ir, self.domains, self.rendered, self.bodies, self.intent, self.storage = fixture()
        self.files = {RELEASE / name: body for name, body in self.bodies.items()}
        self.sync()
        self.stack = self.enterContext(mock.patch.multiple(o, lock_held=mock.DEFAULT, pointer=mock.DEFAULT,
                 inventory=mock.DEFAULT, storage_binding=mock.DEFAULT, boot_id=mock.DEFAULT, read_file=mock.DEFAULT))
        self.stack['lock_held'].return_value = True
        self.stack['pointer'].return_value = True
        self.stack['inventory'].return_value = self.rendered
        self.stack['storage_binding'].return_value = (self.storage, {})
        self.stack['boot_id'].return_value = BOOT
        self.stack['read_file'].side_effect = self.reader
        self.enterContext(mock.patch.object(o.Selection, 'installed_sources', return_value=True))
        self.enterContext(mock.patch.object(o.time, 'monotonic', return_value=10.0))
        self.enterContext(mock.patch.object(o.subprocess, 'run', side_effect=AssertionError('NO host operations')))

    def sync(self):
        raw = encoded(self.intent)
        self.files[ROOT / '.install-intent.json'] = raw
        self.files[RELEASE / 'installation-receipt.json'] = raw

    def reader(self, path, **kwargs):
        if Path(path) not in self.files: raise FileNotFoundError()
        return self.files[Path(path)]

    def select(self, phase=None):
        return o.Selection(ROOT, RELEASE, self.intent, phase or self.intent['phase'])

    def sealed(self):
        return o.seal_selection(ROOT, RELEASE, self.intent)

    def test_seal_before_bootstrap_exact_inventory_and_original_start(self):
        proof = self.sealed()
        self.assertEqual(proof['bootId'], BOOT)
        self.assertEqual(proof['startMonotonicUSec'], 10_000_000)
        self.assertEqual(proof['renderedInputs'], {k: o.r.sha(v) for k, v in self.rendered.items()})
        self.assertEqual(proof['storageBinding'], self.storage)
        self.assertNotIn('images', proof)
        self.assertEqual(self.intent['phase'], 'preparing')
        self.stack['lock_held'].assert_called()

    def test_receipt_must_be_byte_identical_not_merely_json_equal(self):
        self.files[RELEASE / 'installation-receipt.json'] = json.dumps(self.intent, indent=1).encode()
        with self.assertRaises(o.Refused): self.sealed()

    def test_prior_intent_must_equal_current(self):
        self.files[ROOT / '.install-intent.json'] = encoded(dict(self.intent, phase='failed'))
        with self.assertRaises(o.Refused): self.sealed()

    def test_duplicate_intent_keys_refused(self):
        self.files[ROOT / '.install-intent.json'] = b'{"schemaVersion":1,"schemaVersion":1}'
        with self.assertRaises(o.Refused): self.sealed()

    def test_changed_cas_even_same_json_refused(self):
        selection = self.select(); selection.snapshot()
        raw = json.dumps(self.intent, indent=1).encode()
        self.files[ROOT / '.install-intent.json'] = raw
        self.files[RELEASE / 'installation-receipt.json'] = raw
        with self.assertRaises(o.Refused): selection.snapshot()

    def test_current_pointer_failure_refused(self):
        self.stack['pointer'].side_effect = o.Refused('current drift')
        with self.assertRaises(o.Refused): self.sealed()

    def test_lock_failure_refused_without_mutation(self):
        before = copy.deepcopy(self.files)
        self.stack['lock_held'].side_effect = o.Refused('no inherited lock')
        with self.assertRaises(o.Refused): self.sealed()
        self.assertEqual(before, self.files)

    def test_changed_and_missing_core_hashes_refused(self):
        for body in (b'changed', None):
            with self.subTest(body=body):
                if body is None: self.files.pop(RELEASE / 'bundle.json', None)
                else: self.files[RELEASE / 'bundle.json'] = body
                with self.assertRaises(o.Refused): self.sealed()

    def test_missing_expanded_pins_refused(self):
        self.intent['inputs'].pop('site/agent-vm.json'); self.sync()
        with self.assertRaises(o.Refused): self.sealed()

    def test_previously_absent_optional_input_cannot_appear(self):
        self.files[RELEASE / 'site/components.lock.json'] = b'{}'
        with self.assertRaises(o.Refused): self.sealed()

    def test_safe_root_release_and_phase_required(self):
        for root, release, intent in [(ROOT, Path('/elsewhere/r1'), self.intent),
                (ROOT, RELEASE, dict(self.intent, schemaVersion=True)),
                (ROOT, RELEASE, dict(self.intent, phase='failed')),
                (Path('/sealed/../sealed'), RELEASE, self.intent)]:
            with self.subTest(root=root, release=release):
                with self.assertRaises(o.Refused): o.Selection(root, release, intent, 'preparing')

    def test_cannot_reseal_attempt(self):
        self.intent['readiness'] = self.sealed(); self.sync()
        with self.assertRaises(o.Refused): self.sealed()

    def test_boot_rendered_marker_and_start_drift_refused(self):
        proof = self.sealed(); self.intent.update(phase='building', readiness=proof)
        variants = [('bootId', 'wrong'), ('renderedInputs', {}), ('storageBinding', {}),
                    ('startMonotonicUSec', 0), ('startMonotonicUSec', True), ('startMonotonicUSec', 99_000_000)]
        for key, value in variants:
            with self.subTest(key=key):
                self.intent['readiness'] = dict(proof, **{key: value}); self.sync()
                with self.assertRaises(o.Refused): self.select().snapshot()

    def test_seal_drift_during_second_snapshot_refused(self):
        original = self.stack['inventory'].return_value
        changed = dict(original); changed.pop(next(iter(changed)))
        self.stack['inventory'].side_effect = [original, changed]
        with self.assertRaises(o.Refused): self.sealed()

    def test_storage_overlap_refused(self):
        self.storage['scope'] = str(ROOT / 'data')
        with self.assertRaises(o.Refused): self.sealed()


class OwnerAPITests(unittest.TestCase):
    def setUp(self):
        self.ir, self.domains, self.rendered, _, self.intent, self.storage = fixture()
        self.plan = o.r.derive_plan(self.ir, self.domains, self.rendered)
        self.data = f.observations(self.plan)
        self.proof = {'schemaVersion': 1, 'bootId': BOOT, 'startMonotonicUSec': 1_000_000,
                      'renderedInputs': {k: o.r.sha(v) for k, v in self.rendered.items()}, 'storageBinding': self.storage}
        self.intent.update(phase='building', readiness=self.proof)
        self.selection = mock.Mock(plan=self.plan, ir=self.ir, domains=self.domains, rendered=self.rendered,
                                   release=RELEASE, cas='c' * 64)
        self.selection.left.return_value = 119
        self.binding = {'readiness': self.proof, 'cas': 'c' * 64}
        self.selection.snapshot.return_value = self.binding
        self.commands = {s: (['selected-manager', s], ['selected-store', s]) for s in {u.scope for u in self.plan}}
        self.selection.commands.return_value = self.commands
        self.selection.account.side_effect = lambda s: None if s == 'rootful' else types.SimpleNamespace(pw_name='svc-apps')
        self.selection.source_identity.side_effect = lambda u, s, f: {'source': u.source, 'fragment': u.name, 'hash': 'reviewed'}
        self.selection.run.side_effect = self.query_run
        self.calls = []
        self.enterContext(mock.patch.object(o, 'Selection', return_value=self.selection))
        self.enterContext(mock.patch.object(o.subprocess, 'run', side_effect=AssertionError('NO host operations')))

    def query_run(self, argv, *, timeout):
        self.calls.append(argv)
        self.assertGreater(timeout, 0)
        if 'show' in argv:
            scope = argv[1]; names = argv[argv.index('--') + 1:]
            rows = self.data['units'][scope]
            text = '\n\n'.join('\n'.join(k + '=' + v for k, v in rows[n].items()) for n in names)
            return types.SimpleNamespace(returncode=0, stdout=text)
        if 'image' in argv:
            self.assertEqual(argv[2:7], ['image', 'inspect', '--format', '{{.Id}}', '--'])
            return types.SimpleNamespace(returncode=0, stdout=IMAGE + '\n')
        if 'container' in argv:
            scope = argv[1]
            return types.SimpleNamespace(returncode=0, stdout='\n'.join(encoded(v).decode() for v in self.data['containers'][scope].values()))
        raise AssertionError('unapproved command')

    def capture(self):
        return o.capture_images(ROOT, RELEASE, self.intent)

    def starting(self):
        self.intent['readiness'] = self.capture(); self.intent['phase'] = 'starting'
        self.binding = {'cas': 'c' * 64, 'readiness': copy.deepcopy(self.intent['readiness'])}
        self.selection.snapshot.return_value = self.binding
        return self.intent['readiness']

    def test_capture_exact_all_required_services_including_oneshots(self):
        proof = self.capture()
        self.assertEqual(sum(map(len, proof['images'].values())), len(self.plan))
        self.assertTrue(proof['imageSupplyReviewed'])
        self.assertEqual(proof['startMonotonicUSec'], 1_000_000)
        self.assertNotIn('images', self.intent['readiness'])
        image_queries = [a for a in self.calls if 'image' in a]
        self.assertEqual(len(image_queries), len(self.plan))
        self.assertTrue(all('selected-store' == a[0] for a in image_queries))

    def test_engineering_build_tag_captured_explicitly_unreviewed(self):
        self.ir['services']['app'].pop('frozenBuildImage')
        source = 'quadlet/rootless-apps/webservices-app.container'
        self.rendered[source] = self.rendered[source].replace(IMAGE.encode(), b'webservices-app.build')
        self.plan = o.r.derive_plan(self.ir, self.domains, self.rendered); self.selection.plan = self.plan
        proof = self.capture()
        row = proof['images']['rootless-apps']['webservices-app.service']
        self.assertEqual(row['reference'], 'localhost/webservices/app:bundle')
        self.assertEqual(row['configId'], IMAGE)
        self.assertFalse(row['supplyReviewed']); self.assertFalse(proof['imageSupplyReviewed'])

    def test_frozen_config_mismatch_refused(self):
        self.selection.run.side_effect = lambda a, timeout: (types.SimpleNamespace(returncode=0, stdout='sha256:' + 'f' * 64)
                                                            if 'image' in a else self.query_run(a, timeout=timeout))
        with self.assertRaises(o.Refused): self.capture()

    def test_bad_image_ids_never_captured(self):
        for output in ('', 'tag:latest', 'a' * 63, IMAGE + '\n' + IMAGE):
            with self.subTest(output=output):
                self.selection.run.side_effect = lambda a, timeout: (types.SimpleNamespace(returncode=0, stdout=output)
                                                                    if 'image' in a else self.query_run(a, timeout=timeout))
                with self.assertRaises(o.Refused): self.capture()

    def test_unloaded_or_dropin_at_capture_refused(self):
        row = self.data['units']['rootful']['webservices-edge.service']
        for key, value in [('LoadState', 'masked'), ('DropInPaths', '/foreign/dropin')]:
            original = row[key]; row[key] = value
            with self.assertRaises(o.Refused): self.capture()
            row[key] = original

    def test_captured_early_attempt_start_never_reset(self):
        proof = self.capture()
        self.assertEqual(proof['startMonotonicUSec'], self.proof['startMonotonicUSec'])

    def test_missing_seal_or_repeated_capture_refused(self):
        self.intent['readiness'] = {}
        with self.assertRaises(o.Refused): self.capture()
        self.intent['readiness'] = dict(self.proof, images={})
        with self.assertRaises(o.Refused): self.capture()

    def test_frozen_supply_needs_frozen_ir_flag(self):
        self.ir['quadletBuildImagesFrozen'] = False
        with self.assertRaises(o.Refused): self.capture()

    def test_changed_selection_after_capture_refused(self):
        self.selection.snapshot.side_effect = [self.binding, {'cas': 'different'}]
        with self.assertRaises(o.Refused): self.capture()

    def test_verify_calls_existing_graph_exact_bounds_and_callbacks(self):
        proof = self.starting()
        def graph(plan, **kw):
            self.assertEqual(plan, self.plan)
            self.assertEqual(kw['stable_seconds'], 10); self.assertLessEqual(kw['timeout_seconds'], 120)
            self.assertEqual(kw['poll_seconds'], 1)
            self.assertEqual(kw['attempt_start_us'], 1_000_000)
            self.assertEqual(kw['runtime_matches'], self.selection.runtime_matches)
            kw['recheck']()
            for u in plan: self.assertTrue(kw['source_matches'](u, u.source, u.name))
            return {'applicationAcceptance': False, 'samples': 11}
        with mock.patch.object(o.r, 'verify_graph', side_effect=graph):
            result = o.verify_active_transition(ROOT, RELEASE, self.intent)
        self.assertFalse(result['applicationAcceptance']); self.assertFalse(result['immutableSupplyAcceptance'])
        self.assertTrue(result['imageSupplyReviewed'])
        self.assertEqual(result['intentSha256'], 'c' * 64)

    def test_full_graph_owner_integration_stable_ten_seconds_no_real_sleep(self):
        self.starting(); clock = [10.0]; verify = o.r.verify_graph
        def graph(plan, **kw):
            return verify(plan, **kw, clock=lambda: clock[0], sleep=lambda s: clock.__setitem__(0, clock[0] + s))
        self.selection.runtime_matches.return_value = True
        with mock.patch.object(o.r, 'verify_graph', side_effect=graph):
            result = o.verify_active_transition(ROOT, RELEASE, self.intent)
        self.assertGreaterEqual(result['stableSeconds'], 10)
        self.assertFalse(result['applicationAcceptance'])
        self.assertGreater(self.selection.snapshot.call_count, 10)

    def test_full_graph_owner_integration_late_earlier_domain_failure(self):
        self.starting(); clock = [10.0]; verify = o.r.verify_graph
        def sleep(seconds):
            clock[0] += seconds
            if clock[0] >= 19:
                self.data['units']['rootful']['webservices-edge.service']['Result'] = 'exit-code'
        def graph(plan, **kw):
            return verify(plan, **kw, clock=lambda: clock[0], sleep=sleep)
        self.selection.runtime_matches.return_value = True
        with mock.patch.object(o.r, 'verify_graph', side_effect=graph):
            with self.assertRaises(o.Refused): o.verify_active_transition(ROOT, RELEASE, self.intent)

    def test_verify_stored_reference_drift_refused(self):
        proof = self.starting()
        proof['images']['rootful']['webservices-edge.service']['reference'] = 'foreign:tag'
        with mock.patch.object(o.r, 'verify_graph', side_effect=lambda p, **kw: kw['recheck']()):
            with self.assertRaises(o.Refused): o.verify_active_transition(ROOT, RELEASE, self.intent)

    def test_verify_store_identity_drift_including_oneshots_refused(self):
        self.starting()
        self.selection.run.side_effect = lambda a, timeout: types.SimpleNamespace(returncode=0, stdout='f' * 64)
        with mock.patch.object(o.r, 'verify_graph', side_effect=lambda p, **kw: kw['recheck']()):
            with self.assertRaises(o.Refused): o.verify_active_transition(ROOT, RELEASE, self.intent)

    def test_verify_exact_scope_and_service_maps(self):
        proof = self.starting()
        for field in ('images', 'loadedInputs'):
            original = copy.deepcopy(proof[field]); proof[field]['foreign'] = {}
            with self.assertRaises(o.Refused): o.verify_active_transition(ROOT, RELEASE, self.intent)
            proof[field] = original
            proof[field]['rootful']['unselected.service'] = {}
            with self.assertRaises(o.Refused): o.verify_active_transition(ROOT, RELEASE, self.intent)
            proof[field] = original

    def test_verify_supply_flag_cannot_overclaim(self):
        proof = self.starting(); proof['imageSupplyReviewed'] = False
        with self.assertRaises(o.Refused): o.verify_active_transition(ROOT, RELEASE, self.intent)

    def test_failed_graph_never_mutates_evidence(self):
        self.starting(); before = copy.deepcopy(self.intent)
        with mock.patch.object(o.r, 'verify_graph', side_effect=o.Refused('selected oneshot failed')):
            with self.assertRaises(o.Refused): o.verify_active_transition(ROOT, RELEASE, self.intent)
        self.assertEqual(self.intent, before)


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = self.enterContext(tempfile.TemporaryDirectory(prefix='owner-isolated-'))
        self.base = Path(self.temp); self.path = self.base / 'authority'
        self.path.write_bytes(b'reviewed'); self.path.chmod(0o600)
        # ONLY the temp test harness bypasses root ancestry; production has no
        # test-root/environment flag. File UID/link/type checks remain real.
        self.enterContext(mock.patch.object(o, 'root_directory'))
        self.uid = self.path.stat().st_uid

    def read(self, path=None, **kw):
        return o.read_file(path or self.path, owner=self.uid, **kw)

    def test_descriptor_read_and_exact_private_mode(self):
        self.assertEqual(self.read(private=True), b'reviewed')
        self.path.chmod(0o644)
        with self.assertRaises(o.Refused): self.read(private=True)

    def test_final_symlink_rejected(self):
        target = self.base / 'link'; target.symlink_to(self.path)
        with self.assertRaises(OSError): self.read(target)

    def test_ancestor_symlink_rejected(self):
        real = self.base / 'real'; real.mkdir(); (real / 'file').write_bytes(b'x')
        link = self.base / 'linked'; link.symlink_to(real)
        with self.assertRaises(OSError): self.read(link / 'file')

    def test_hardlink_rejected(self):
        os.link(self.path, self.base / 'alias')
        with self.assertRaises(o.Refused): self.read()

    def test_fifo_rejected_without_blocking(self):
        fifo = self.base / 'fifo'; os.mkfifo(fifo)
        with self.assertRaises(o.Refused): self.read(fifo)

    def test_wrong_owner_writable_and_oversize_rejected(self):
        with self.assertRaises(o.Refused): o.read_file(self.path, owner=self.uid + 1)
        with self.assertRaises(o.Refused): self.read(limit=2)
        self.path.chmod(0o620)
        with self.assertRaises(o.Refused): self.read()

    def test_exact_directory_exception_not_arbitrary_ancestor_allowance(self):
        pin = o.directory_pin(self.base)
        self.assertEqual(self.read(directories={self.base: pin}), b'reviewed')
        with self.assertRaises(o.Refused): self.read(directories={self.base: (self.uid + 1, pin[1], pin[2])})

    def test_noncanonical_path_refused(self):
        with self.assertRaises(o.Refused): self.read(str(self.base) + '/../escape')

    def test_native_pointer_only_exact_owned_link(self):
        root = self.base / 'root'; root.mkdir(); release = root / 'releases/r1'
        (root / 'current').symlink_to(str(release))
        self.assertTrue(o.pointer(root, release, owners=(self.uid,)))
        with self.assertRaises(o.Refused): o.pointer(root, release.parent / 'r2', owners=(self.uid,))
        (root / 'current').unlink(); (root / 'current').write_bytes(b'not link')
        with self.assertRaises(o.Refused): o.pointer(root, release)


class RuntimeCallbackTests(unittest.TestCase):
    def setUp(self):
        ir, domains, rendered, _, self.intent, _ = fixture()
        self.unit = next(u for u in o.r.derive_plan(ir, domains, rendered) if u.scope == 'rootful' and u.role == 'daemon')
        self.selection = o.Selection(ROOT, RELEASE, self.intent, 'preparing')
        self.selection.ir = ir; self.selection.domains = domains; self.selection.rendered = rendered
        self.selection.prior['readiness'] = {'images': {self.unit.scope: {self.unit.name: {'configId': IMAGE}}}}
        self.container = f.observations([self.unit])['containers'][self.unit.scope][self.unit.container]
        self.props = f.observations([self.unit])['units'][self.unit.scope][self.unit.name]
        self.container['conmonPid'] = int(self.props['MainPID'])
        self.cid = self.container['id'].encode() + b'\n'
        self.process = {'uid': 0, 'cgroup': self.props['ControlGroup'], 'startTicks': 123}
        self.reader = self.enterContext(mock.patch.object(o, 'read_file', return_value=self.cid))
        self.proc = self.enterContext(mock.patch.object(o, 'process_fields', return_value=self.process))
        self.enterContext(mock.patch.object(o.subprocess, 'run', side_effect=AssertionError('NO host operations')))

    def matches(self):
        return self.selection.runtime_matches(self.unit, self.props, self.container)

    def test_selected_cid_conmon_pid_cgroup_image(self):
        self.assertTrue(self.matches())
        self.assertEqual(self.reader.call_args.args[0], Path('/run/webservices-edge.cid'))
        self.proc.assert_called_with(self.container['conmonPid'], 0)

    def test_unrelated_same_name_container_cannot_match(self):
        for field, value in [('id', 'f' * 64), ('image', 'sha256:' + 'f' * 64), ('conmonPid', 999)]:
            original = self.container[field]; self.container[field] = value
            with self.assertRaises(o.Refused): self.matches()
            self.container[field] = original

    def test_wrong_or_changed_process_cgroup_identity_refused(self):
        self.proc.return_value = dict(self.process, cgroup='/foreign.service')
        with self.assertRaises(o.Refused): self.matches()
        self.proc.side_effect = [self.process, dict(self.process, startTicks=124)]
        with self.assertRaises(o.Refused): self.matches()

    def test_changed_cid_after_process_read_refused(self):
        self.reader.side_effect = [self.cid, b'changed']
        with self.assertRaises(o.Refused): self.matches()

    def test_loaded_source_hash_fragment_path_and_execution(self):
        source = '/etc/containers/systemd/webservices-edge.container'
        fragment = '/run/systemd/generator/webservices-edge.service'
        raw_source = self.selection.rendered[self.unit.source]
        body = ('[Unit]\nSourcePath=' + source + '\n[Service]\nExecStart=/usr/bin/podman run \\\n --cidfile=%t/%N.cid ' + IMAGE + '\n').encode()
        self.reader.side_effect = [raw_source, body]
        result = self.selection.source_identity(self.unit, source, fragment)
        self.assertEqual(result['fragmentSha256'], o.r.sha(body))
        for s, p in [(source + '.foreign', fragment), (source, '/foreign/fragment')]:
            with self.assertRaises(o.Refused): self.selection.source_identity(self.unit, s, p)

    def test_foreign_loaded_fragment_even_with_correct_source_path(self):
        source = '/etc/containers/systemd/webservices-edge.container'
        fragment = '/run/systemd/generator/webservices-edge.service'
        for directive in ['ExecStart=/bin/true', 'ExecStart=/usr/bin/podman run --cidfile=/foreign ' + IMAGE,
                          'ExecStart=/usr/bin/podman run --cidfile=%t/%N.cid foreign:tag']:
            self.reader.side_effect = [self.selection.rendered[self.unit.source],
                                      ('[Unit]\nSourcePath=' + source + '\n[Service]\n' + directive + '\n').encode()]
            with self.assertRaises(o.Refused): self.selection.source_identity(self.unit, source, fragment)


class AccountCommandTests(unittest.TestCase):
    def setUp(self):
        ir, domains, rendered, _, intent, _ = fixture()
        self.selection = o.Selection(ROOT, RELEASE, intent, 'preparing')
        self.selection.ir = ir; self.selection.domains = domains; self.selection.rendered = rendered
        self.selection.plan = o.r.derive_plan(ir, domains, rendered)
        def account(user):
            row = next(d for d in domains['domains'] if d['user'] == user)
            return types.SimpleNamespace(pw_name=user, pw_uid=row['uid'], pw_gid=row['uid'], pw_dir='/home/' + user)
        self.enterContext(mock.patch.object(o.pwd, 'getpwnam', side_effect=account))
        self.enterContext(mock.patch.object(self.selection, 'actor_custody', return_value={}))
        self.rootful = self.enterContext(mock.patch.object(o.images, 'rootful_command', return_value=['exact-rootful-store']))
        self.pointer = self.enterContext(mock.patch.object(o, 'pointer', return_value=True))
        self.reader = self.enterContext(mock.patch.object(o, 'read_file', side_effect=self.read))
        self.enterContext(mock.patch.object(o.subprocess, 'run', side_effect=AssertionError('NO host operations')))

    def read(self, path, **kw):
        if path.name == 'storage.conf':
            return b'[storage]\ndriver = "overlay"\ngraphroot = "/scope/apps/graphRoot"\n'
        if path.name == 'containers.conf':
            return b'[network]\ndefault_rootless_network_cmd = "pasta"\npasta_options = ["--map-host-loopback", "169.254.1.2"]\n'
        return self.selection.rendered['quadlet/rootless-apps/' + path.name]

    def test_commands_only_pinned_rootful_and_exact_actor_home_bus_store(self):
        commands = self.selection.commands()
        self.rootful.assert_called_once_with(RELEASE)
        self.assertEqual(commands['rootful'][1], ['exact-rootful-store'])
        manager, podman = commands['rootless-apps']
        self.assertIn('HOME=/home/svc-apps', manager)
        self.assertIn('XDG_RUNTIME_DIR=/run/user/780', manager)
        self.assertIn('DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/780/bus', manager)
        self.assertEqual(manager[-2:], ['systemctl', '--user'])
        self.assertIn('-i', manager)
        self.assertEqual(podman[-5:], ['podman', '--root', '/scope/apps/graphRoot', '--runroot', '/run/user/780/containers'])
        self.assertNotIn('rootless-empty', commands)
        self.pointer.assert_called_once_with(Path('/scope/apps/stateRoot'), Path('/scope/apps/stateRoot/releases/r1'),
                                             directories={}, owners=(0, 780))

    def test_bad_runtime_config_or_actor_release_source_refused(self):
        self.reader.side_effect = None; self.reader.return_value = b'foreign'
        with self.assertRaises(o.Refused): self.selection.commands()

    def test_installed_sources_covers_targets_networks_builds_and_empty_managers(self):
        expected = {}
        for name, body in self.selection.rendered.items():
            _, scope, filename = Path(name).parts
            if scope == 'rootful':
                base = Path('/etc/systemd/system' if name.endswith('.target') else '/etc/containers/systemd')
            else:
                user = next(d['user'] for d in self.selection.domains['domains'] if 'rootless-' + d['name'] == scope)
                base = Path('/home') / user / ('.config/systemd/user' if name.endswith('.target') else '.config/containers/systemd')
            expected[base / filename] = body
        self.reader.side_effect = lambda path, **kw: expected[path]
        self.assertTrue(self.selection.installed_sources())
        self.assertEqual({call.args[0] for call in self.reader.call_args_list}, set(expected))
        self.reader.side_effect = lambda path, **kw: b'foreign'
        with self.assertRaises(o.Refused): self.selection.installed_sources()

    def test_runner_scrubs_environment_bounds_deadline_and_preserves_fd9(self):
        # No subprocess is executed: inspect the exact bounded call contract.
        with mock.patch.object(o.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0, stdout='scalar')) as run:
            self.selection.run(['selected', 'query'], timeout=30)
        self.assertLessEqual(run.call_args.kwargs['timeout'], 20)
        self.assertEqual(run.call_args.kwargs['env'], {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
        self.assertEqual(run.call_args.kwargs['pass_fds'], (9,))
        self.assertEqual(run.call_args.kwargs['cwd'], '/')


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.scope = Path('/scope')
        self.operator = types.SimpleNamespace(pw_uid=1000, pw_gid=1000)
        self.row = {'name': 'apps', 'user': 'actor', 'uid': 780,
                    'stateRoot': '/scope/state/apps', 'graphRoot': '/scope/graph/apps', 'volumeRoot': '/scope/volumes/apps'}
        self.expected = {'domains': [self.row]}
        self.account = types.SimpleNamespace(pw_uid=780, pw_gid=780, pw_dir='/home/actor')
        self.acl = {('user', ''): 'rwx', ('group', ''): 'rwx', ('mask', ''): 'rwx',
                    ('other', ''): '---', ('user', '780'): '--x', ('user', '100000'): '--x'}
        self.authority = self.enterContext(mock.patch.object(o.storage, 'authority', return_value=(self.scope, self.operator, self.expected)))
        self.marker = self.enterContext(mock.patch.object(o.storage, 'marker'))
        self.safe = self.enterContext(mock.patch.object(o.storage, 'safe_parent'))
        self.enterContext(mock.patch.object(o.storage, 'namespace_root_id', return_value=100000))
        self.entries = self.enterContext(mock.patch.object(o.storage, 'entries', return_value=self.acl))
        self.enterContext(mock.patch.object(o.pwd, 'getpwnam', return_value=self.account))
        self.enterContext(mock.patch.object(o.grp, 'getgrnam', return_value=types.SimpleNamespace(gr_gid=1000)))
        self.pin = self.enterContext(mock.patch.object(o, 'directory_pin', side_effect=lambda p:
                      (780, 780, 0o700) if str(p) in [self.row[k] for k in ('stateRoot', 'graphRoot', 'volumeRoot')]
                      else (1000, 1000, 0o2770)))
        self.reader = self.enterContext(mock.patch.object(o, 'read_file', return_value=encoded(self.expected)))
        self.enterContext(mock.patch.object(o, 'root_directory'))
        self.enterContext(mock.patch.object(Path, 'lstat', return_value=types.SimpleNamespace(st_dev=1, st_ino=2,
                          st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o600, st_nlink=1)))
        self.enterContext(mock.patch.object(o.subprocess, 'run', side_effect=AssertionError('NO host operations')))

    def test_operator_group_writable_scope_uses_canonical_marker_and_safe_parent(self):
        pin, custody = o.storage_binding(RELEASE)
        self.authority.assert_called_once_with(RELEASE)
        self.marker.assert_called_once_with(self.scope, self.expected)
        self.safe.assert_any_call(self.scope, self.operator)
        self.assertEqual(custody[self.scope], (1000, 1000, 0o2770))
        self.assertEqual(pin['markerSha256'], o.r.sha(encoded(self.expected)))
        self.assertIn('markerIdentity', pin)
        self.assertIn('/scope/graph/apps', pin['directoryIdentities'])
        self.reader.assert_called_once_with(self.scope / o.storage.MARKER, private=True, directories=custody, limit=65536)

    def test_unreviewed_operator_actor_or_scope_modes_refused(self):
        self.operator.pw_uid = 1001
        with self.assertRaises(o.Refused): o.storage_binding(RELEASE)
        self.operator.pw_uid = 1000; self.row['uid'] = 1001
        with self.assertRaises(o.Refused): o.storage_binding(RELEASE)
        self.row['uid'] = 780; self.pin.side_effect = None; self.pin.return_value = (1000, 1000, 0o777)
        with self.assertRaises(o.Refused): o.storage_binding(RELEASE)

    def test_foreign_acl_read_write_or_unselected_execute_refused(self):
        for key, value in [(('user', '999'), '--x'), (('user', '780'), 'rwx'),
                           (('group', '1000'), '--x'), (('other', ''), '--x')]:
            original = dict(self.acl); self.acl[key] = value
            with self.assertRaises(o.Refused): o.storage_binding(RELEASE)
            self.acl.clear(); self.acl.update(original)

    def test_insufficient_deadline_never_starts_canonical_acl_query(self):
        with self.assertRaises(o.Refused): o.storage_binding(RELEASE, remaining=lambda: 9)
        self.authority.assert_not_called()
        self.entries.assert_not_called()

    def test_changed_marker_body_refused_without_permission_repair(self):
        self.reader.return_value = b'{}'
        with self.assertRaises(o.Refused): o.storage_binding(RELEASE)
        self.safe.assert_any_call(self.scope, self.operator)


class ProcessTests(unittest.TestCase):
    def test_kernel_scalar_uid_cgroup_start_only(self):
        stat_body = ('123 (conmon) S ' + ' '.join(['0'] * 18) + ' 456\n').encode()
        bodies = [b'Name:\tconmon\nUid:\t780\t780\t780\t780\n', b'0::/user.slice/webservices-app.service\n', stat_body]
        with mock.patch.object(o.os, 'open', return_value=123) as opened, mock.patch.object(o.os, 'close'), \
             mock.patch.object(o.os, 'read', side_effect=bodies):
            result = o.process_fields(123, 780)
        self.assertEqual(result, {'uid': 780, 'cgroup': '/user.slice/webservices-app.service', 'startTicks': 456})
        self.assertEqual([call.args[0].name for call in opened.call_args_list], ['status', 'cgroup', 'stat'])

    def test_foreign_uid_or_non_unified_cgroup_refused(self):
        for bodies in ([b'Uid:\t0\t0\t0\t0\n'], [b'Uid:\t780\t780\t780\t780\n', b'1:cpu:/foreign\n']):
            with mock.patch.object(o.os, 'open', return_value=123), mock.patch.object(o.os, 'close'), \
                 mock.patch.object(o.os, 'read', side_effect=bodies):
                with self.assertRaises(o.Refused): o.process_fields(123, 780)


class LockTests(unittest.TestCase):
    def info(self):
        return types.SimpleNamespace(st_dev=os.makedev(8, 1), st_ino=42, st_uid=0, st_gid=0,
             st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_size=0, st_mtime_ns=1, st_ctime_ns=1)

    def test_requires_inherited_exclusive_flock_not_an_assertion(self):
        info = self.info(); flock = mock.Mock(side_effect=BlockingIOError(errno.EAGAIN, 'held'))
        with mock.patch.object(o.r, 'read_owned', return_value=b''), mock.patch.object(Path, 'lstat', return_value=info), \
             mock.patch.object(o.os, 'fstat', return_value=info), mock.patch.object(o.os, 'open', return_value=123), \
             mock.patch.object(o.os, 'close'), mock.patch.object(o.fcntl, 'flock', flock), \
             mock.patch('builtins.open', return_value=io.StringIO('lock:\t1: FLOCK ADVISORY WRITE 12 08:01:42 0 EOF\n')):
            self.assertTrue(o.lock_held(ROOT))
            flock.assert_called_once_with(123, o.fcntl.LOCK_EX | o.fcntl.LOCK_NB)

    def test_unlocked_descriptor_and_wrong_inode_refused(self):
        info = self.info()
        for text in ('pos: 0\n', 'lock:\t1: FLOCK ADVISORY READ 12 08:01:42 0 EOF\n',
                     'lock:\t1: FLOCK ADVISORY WRITE 12 08:01:99 0 EOF\n'):
            with mock.patch.object(o.r, 'read_owned', return_value=b''), mock.patch.object(Path, 'lstat', return_value=info), \
                 mock.patch.object(o.os, 'fstat', return_value=info), mock.patch('builtins.open', return_value=io.StringIO(text)), \
                 mock.patch.object(o.fcntl, 'flock', side_effect=AssertionError('must not acquire FD9')):
                with self.assertRaises(o.Refused): o.lock_held(ROOT)

    def test_competing_descriptor_must_be_excluded(self):
        info = self.info()
        with mock.patch.object(o.r, 'read_owned', return_value=b''), mock.patch.object(Path, 'lstat', return_value=info), \
             mock.patch.object(o.os, 'fstat', return_value=info), mock.patch.object(o.os, 'open', return_value=123), \
             mock.patch.object(o.os, 'close'), mock.patch.object(o.fcntl, 'flock') as flock, \
             mock.patch('builtins.open', return_value=io.StringIO('lock:\t1: FLOCK ADVISORY WRITE 12 08:01:42 0 EOF\n')):
            with self.assertRaises(o.Refused): o.lock_held(ROOT)
            self.assertTrue(all(call.args[0] != 9 for call in flock.call_args_list))


class ActualParentACLTests(unittest.TestCase):
    def test_canonical_operator_and_public_volume_ancestor_preserve_authored_mask(self):
        acl = {('user', ''): 'rwx', ('group', ''): 'rwx\t#effective:r-x',
               ('mask', ''): 'r-x', ('other', ''): 'r-x',
               ('user', '1000'): 'rwx\t#effective:r-x', ('user', '780'): '--x'}
        with mock.patch.object(o.storage, 'entries', return_value=acl):
            self.assertEqual(o.check_acl(Path('/fixture/volumes'), {780}, operator_uid=1000, public=True), acl)
            with self.assertRaises(ValueError):
                o.check_acl(Path('/fixture/graphs'), {780}, operator_uid=1000)
            with self.assertRaises(ValueError):
                o.check_acl(Path('/fixture/volumes'), {780}, operator_uid=1001, public=True)


if __name__ == '__main__':
    unittest.main()
