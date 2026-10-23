#!/usr/bin/env python3
"""Isolated source/mock proof only. No native runtime, real account or host reads."""
import copy
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
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/native-selection.py'
spec = importlib.util.spec_from_file_location('native_selection_under_test', SOURCE)
n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n)


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json.dumps(value, sort_keys=True).encode() if isinstance(value, dict) else value)
    path.chmod(0o644)


def fixture(bundle):
    ir = {'schemaVersion': 1, 'networks': {'default': {}}, 'services': {
        'edge': {'placement': 'rootful', 'lifecycle': 'daemon', 'target': 'core', 'networks': ['default']},
        'app': {'placement': 'rootless', 'rootlessDomain': 'apps', 'lifecycle': 'daemon'},
        'keycloak-configure': {'placement': 'rootless', 'rootlessDomain': 'apps', 'lifecycle': 'oneshot'},
        'firefly-identity-check': {'placement': 'rootless', 'rootlessDomain': 'apps', 'lifecycle': 'oneshot'},
        'bootstrap': {'placement': 'rootless', 'rootlessDomain': 'apps', 'lifecycle': 'on-demand', 'build': {}},
        'managed-client': {'placement': 'rootless', 'rootlessDomain': 'apps', 'lifecycle': 'on-demand', 'quadletManaged': True},
        'client': {'placement': 'rootless', 'rootlessDomain': 'apps', 'lifecycle': 'on-demand'},
    }}
    for service in ir['services'].values(): service['image'] = 'sha256:' + 'a' * 64
    ir['services']['bootstrap']['frozenBuildImage'] = ir['services']['bootstrap']['image']
    domains = {'schemaVersion': 1, 'deploymentMode': 'standalone', 'domains': [
        {'name': name, 'uid': n.IDENTITIES[name][0], 'user': n.IDENTITIES[name][1],
         'services': [name for name, row in ir['services'].items() if row.get('rootlessDomain') == name_domain],
         'persistentServices': [name for name, row in ir['services'].items()
                                if row.get('rootlessDomain') == name_domain and row['lifecycle'] == 'daemon']}
        for name in ('apps', 'platform') for name_domain in (name,)]}
    put(bundle / 'bundle.json', {'backend': 'podman'})
    put(bundle / 'stack.ir.json', ir)
    put(bundle / 'podman-domains.json', domains)
    for name, service in ir['services'].items():
        role = service['lifecycle']
        if role == 'on-demand' and not (service.get('quadletManaged') or 'build' in service): continue
        scope = 'rootful' if service['placement'] == 'rootful' else 'rootless-apps'
        body = '[Unit]\nPartOf=webservices-' + service.get('target', 'apps') + '.target\n'
        body += '[Container]\nContainerName=' + name + '\nImage=' + service['image'] + '\n'
        body += '[Service]\n'
        if role == 'oneshot': body += 'Type=oneshot\nRemainAfterExit=yes\nRestart=no\n'
        body += '[Install]\n'
        if role != 'on-demand': body += 'WantedBy=webservices-' + service.get('target', 'apps') + '.target\n'
        put(bundle / 'quadlet' / scope / ('webservices-' + name + '.container'), body.encode())
        if 'build' in service:
            put(bundle / 'quadlet' / scope / ('webservices-' + name + '.build'),
                ('[Build]\nImageTag=localhost/webservices/' + name + ':bundle\n').encode())
    for scope in ('rootful', 'rootless-apps', 'rootless-platform'):
        for target in ('core', 'apps', 'observability'):
            units = []
            for name, row in ir['services'].items():
                placement = 'rootful' if row['placement'] == 'rootful' else 'rootless-' + row['rootlessDomain']
                if placement == scope and row.get('target', 'apps') == target and row['lifecycle'] != 'on-demand':
                    units.append('webservices-' + name + '.service')
            put(bundle / 'quadlet' / scope / ('webservices-' + target + '.target'),
                ('[Unit]\nPartOf=webservices.target\nWants=' + ' '.join(units) + '\n[Install]\nWantedBy=webservices.target\n').encode())
        put(bundle / 'quadlet' / scope / 'webservices.target',
            ('[Unit]\nWants=webservices-core.target webservices-apps.target webservices-observability.target\n'
             '[Install]\nWantedBy=' + ('multi-user.target' if scope == 'rootful' else 'default.target') + '\n').encode())
    put(bundle / 'quadlet/rootful/webservices-default.network', b'[Network]\nNetworkName=webservices_default\n')
    return ir, domains


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-selection-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.bundle = self.base / 'candidate'
        self.ir, self.domains = fixture(self.bundle)
        self.installed = self.base / 'installed'; self.installed.mkdir()
        # Mock ownership in inode metadata only; preserve actual modes/types/
        # nlink/sizes and all no-follow descriptor operations. NEVER chown.
        self.owners = {}
        real_fstat = os.fstat; real_lstat = Path.lstat
        def adjusted(info):
            row = list(info)
            row[4] = self.owners.get((info.st_dev, info.st_ino), 0)
            row[5] = row[4]
            fields = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
            fields.update(st_uid=row[4], st_gid=row[5])
            return types.SimpleNamespace(**fields)
        def fstat(fd): return adjusted(real_fstat(fd))
        def lstat(path, *args, **kwargs): return adjusted(real_lstat(path, *args, **kwargs))
        original_policy = n.directory_policy
        self.original_policy = original_policy
        def policy(path, info, actor=None):
            if path == Path('/tmp'):
                # Exact fixture-only temp ancestor exception, not production.
                self.assertTrue(stat.S_ISDIR(info.st_mode)); return
            original_policy(path, info, actor)
        self.real_destination = n.destination
        def destination(scope, entry, relative):
            return self.installed / scope / Path(relative).name
        def account(user):
            uid = next(uid for uid, name in n.IDENTITIES.values() if name == user)
            return types.SimpleNamespace(pw_uid=uid, pw_dir='/home/' + user)
        for patch in (mock.patch.object(n.os, 'fstat', side_effect=fstat),
                      mock.patch.object(Path, 'lstat', lstat),
                      mock.patch.object(n, 'directory_policy', side_effect=policy),
                      mock.patch.object(n, 'destination', side_effect=destination),
                      mock.patch.object(n.pwd, 'getpwnam', side_effect=account),
                      mock.patch('subprocess.run', side_effect=AssertionError('no subprocess permitted'))):
            patch.start(); self.addCleanup(patch.stop)

    def own(self, path, uid):
        info = path.lstat(); self.owners[(info.st_dev, info.st_ino)] = uid

    def receipt(self, bundle=None, phase='retired-failed', rendered=True):
        bundle = bundle or self.bundle
        value = {'schemaVersion': 1, 'phase': phase, 'release': str(bundle), 'inputs': {
            name: n.sha((bundle / name).read_bytes()) for name in ('bundle.json', 'stack.ir.json', 'podman-domains.json')}}
        if rendered:
            value['readiness'] = {'renderedInputs': {path: info['sha256']
                for entry in n.inventory(bundle).values() for path, info in entry['files'].items()}}
        put(bundle / 'installation-receipt.json', value)
        (bundle / 'installation-receipt.json').chmod(0o600)
        return value

    def install_file(self, relative, source=None):
        source = source or self.bundle
        scope = Path(relative).parts[1]
        entry = n.inventory(source)[scope]
        path = n.destination(scope, entry, relative)
        put(path, (source / relative).read_bytes()); self.own(path, entry['uid'])
        return path

    def cli(self, *args):
        out = io.StringIO(); err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = n.main(['--bundle', str(self.bundle), *args])
        return code, out.getvalue(), err.getvalue()

    def test_all_suffixes_exact_names_and_roles(self):
        plan = n.inventory(self.bundle)
        apps = plan['rootless-apps']; root = plan['rootful']
        self.assertEqual((apps['uid'], apps['user']), (781, 'webservices-lab-apps'))
        self.assertIn('webservices-default-network.service', root['networks'])
        self.assertEqual(apps['builds'], ['webservices-bootstrap-build.service'])
        self.assertIn('webservices-bootstrap.service', apps['services'])
        self.assertNotIn('webservices-client.service', apps['services'])
        self.assertIn('webservices-managed-client.service', apps['services'])
        self.assertEqual(apps['persistent'], ['webservices-app.service', 'webservices-firefly-identity-check.service',
                                              'webservices-keycloak-configure.service'])
        self.assertEqual(apps['daemons'], ['webservices-app.service'])
        self.assertEqual(apps['oneshots'], ['webservices-firefly-identity-check.service', 'webservices-keycloak-configure.service'])
        self.assertNotIn('webservices-bootstrap.service', apps['persistent'])
        self.assertEqual(set(plan['rootless-platform']['units']), set(n.TARGETS))
        for scope, entry in plan.items():
            self.assertEqual(len(entry['units']), len(entry['files']))
            self.assertEqual(set(entry['units']), {v['unit'] for v in entry['files'].values()})
            for path, value in entry['files'].items(): self.assertEqual(value['sha256'], n.sha((self.bundle / path).read_bytes()))

    def test_previous_only_accepts_historical_absent_unmanaged_build_pair(self):
        root = self.bundle / 'quadlet/rootless-apps'
        (root / 'webservices-bootstrap.container').unlink()
        (root / 'webservices-bootstrap.build').unlink()
        with self.assertRaises(ValueError):
            n.inventory(self.bundle)
        old = n.inventory(self.bundle, previous=True)
        self.assertNotIn('webservices-bootstrap.service', old['rootless-apps']['units'])
        put(root / 'webservices-bootstrap.build', b'[Build]\nImageTag=localhost/webservices/bootstrap:bundle\n')
        with self.assertRaises(ValueError):
            n.inventory(self.bundle, previous=True)

    def test_exact_selected_standalone_egress_bridge_not_control_authority(self):
        root = self.bundle / 'quadlet/rootless-apps'
        app = root / 'webservices-app.container'
        put(app, app.read_text().replace('ContainerName=app\n', 'ContainerName=app\nNetwork=webservices-p0-egress.network\n').encode())
        put(root / 'webservices-p0-egress.network', b'[Network]\nNetworkName=webservices_apps_p0-egress\nDriver=bridge\n')
        plan = n.inventory(self.bundle)
        self.assertIn('webservices-p0-egress-network.service', plan['rootless-apps']['networks'])
        put(root / 'webservices-p0-control.network', b'[Network]\nNetworkName=webservices_apps_p0-control\n')
        with self.assertRaises(ValueError):
            n.inventory(self.bundle)

    def test_cli_exact_lists_json_validation_no_acceptance_claim(self):
        code, out, err = self.cli('--scope', 'rootless-apps', '--kind', 'builds')
        self.assertEqual((code, out, err), (0, 'webservices-bootstrap-build.service\n', ''))
        code, out, err = self.cli('--scope', 'rootful', '--kind', 'files')
        self.assertTrue(all(name.startswith('quadlet/rootful/') for name in out.splitlines()))
        self.assertEqual(code, 0)
        code, out, err = self.cli('--json')
        self.assertEqual(code, 0); self.assertFalse(json.loads(out)['applicationAcceptance'])
        code, out, err = self.cli('--validate-installed')
        self.assertEqual(code, 0); self.assertGreater(json.loads(out)['absent'], 0)
        self.assertFalse(json.loads(out)['applicationAcceptance'])
        code, out, err = self.cli('--scope', 'rootless-p0-web', '--kind', 'units')
        self.assertEqual(code, 1); self.assertEqual(out, '')

    def test_sentinel_foreign_and_protected_installed_files_never_read(self):
        for name in ('webservices-foreign.container', 'p0-web.target', 'platform-zero-host-broker.service',
                     'webservices-lanes.container', 'webservices-auto-update.service'):
            put(self.installed / 'rootful' / name, b'DO_NOT_READ_FOREIGN_SENTINEL')
        real = n.read_file
        reads = []
        def read(path, **kwargs):
            reads.append(Path(path)); return real(path, **kwargs)
        with mock.patch.object(n, 'read_file', side_effect=read):
            result = n.validate_installed(self.bundle)
        self.assertEqual(result['byteIdentical'], 0)
        self.assertFalse(any(path.name in ('webservices-foreign.container', 'p0-web.target',
            'platform-zero-host-broker.service', 'webservices-lanes.container', 'webservices-auto-update.service') for path in reads))
        self.assertEqual((self.installed / 'rootful/p0-web.target').read_bytes(), b'DO_NOT_READ_FOREIGN_SENTINEL')

    def test_absent_identical_conflicting_installed_files(self):
        relative = 'quadlet/rootless-apps/webservices-app.container'
        path = self.install_file(relative)
        self.assertEqual(n.validate_installed(self.bundle)['byteIdentical'], 1)
        path.write_bytes(b'FOREIGN_BODY_NEVER_ECHO')
        with self.assertRaises(n.Refused) as caught: n.validate_installed(self.bundle)
        self.assertNotIn('FOREIGN_BODY', str(caught.exception))
        self.assertEqual(path.read_bytes(), b'FOREIGN_BODY_NEVER_ECHO')

    def test_previous_union_separate_hashes_retired_failed_receipt(self):
        previous = self.base / 'previous'; fixture(previous)
        old = previous / 'quadlet/rootless-apps/webservices-app.container'
        old.write_bytes(old.read_bytes() + b'# previous exact source\n')
        self.receipt(previous)
        plan = n.selection(self.bundle, previous)
        key = 'quadlet/rootless-apps/webservices-app.container'
        self.assertNotEqual(plan['sources']['candidate']['scopes']['rootless-apps']['files'][key],
                            plan['sources']['previous']['scopes']['rootless-apps']['files'][key])
        self.assertEqual(plan['sources']['previous']['receipt']['phase'], 'retired-failed')
        self.install_file(key, previous)
        self.assertEqual(n.validate_installed(self.bundle, previous)['byteIdentical'], 1)
        with self.assertRaises(n.Refused): n.validate_installed(self.bundle)
        old.write_bytes(old.read_bytes() + b'# drift\n')
        with self.assertRaises(n.Refused): n.selection(self.bundle, previous)

    def test_previous_only_exact_ids_in_union(self):
        previous = self.base / 'previous'; ir, domains = fixture(previous)
        # Candidate no longer selects the managed client; previous still does.
        del self.ir['services']['managed-client']
        self.domains['domains'][0]['services'].remove('managed-client')
        put(self.bundle / 'stack.ir.json', self.ir); put(self.bundle / 'podman-domains.json', self.domains)
        (self.bundle / 'quadlet/rootless-apps/webservices-managed-client.container').unlink()
        self.receipt(previous)
        plan = n.selection(self.bundle, previous)
        self.assertIn('webservices-managed-client.service', plan['scopes']['rootless-apps']['units'])
        self.assertNotIn('webservices-managed-client.service', plan['sources']['candidate']['scopes']['rootless-apps']['units'])
        path = self.install_file('quadlet/rootless-apps/webservices-managed-client.container', previous)
        path.write_bytes(b'foreign')
        with self.assertRaises(n.Refused): n.validate_installed(self.bundle, previous)

    def test_previous_not_inferred_no_environment_trust(self):
        previous = self.base / 'previous'; fixture(previous)
        with mock.patch.dict(os.environ, {'PREVIOUS': str(previous), 'WEBSERVICES_PREVIOUS': str(previous)}):
            self.assertEqual(set(n.selection(self.bundle)['sources']), {'candidate'})
        with self.assertRaises(n.Refused): n.selection(self.bundle, previous)
        with self.assertRaises(n.Refused): n.selection(self.bundle, self.bundle)

    def test_receipt_source_hash_and_rendered_hash_drift(self):
        self.receipt()
        put(self.bundle / 'bundle.json', {'backend': 'podman', 'changed': True})
        with self.assertRaises(n.Refused): n.selection(self.bundle)
        self.receipt()
        path = self.bundle / 'quadlet/rootful/webservices-edge.container'
        path.write_bytes(path.read_bytes() + b'# changed\n')
        with self.assertRaises(n.Refused): n.selection(self.bundle)

    def test_uid_user_domain_drift_refused(self):
        original = copy.deepcopy(self.domains)
        for key, value in [('uid', 780), ('uid', True), ('user', 'webservices-apps'), ('name', 'p0-web'),
                           ('name', 'lanes'), ('user', 'root')]:
            with self.subTest(key=key, value=value):
                domains = copy.deepcopy(original); domains['domains'][0][key] = value
                put(self.bundle / 'podman-domains.json', domains)
                with self.assertRaises(n.Refused): n.inventory(self.bundle)
        put(self.bundle / 'podman-domains.json', original)

    def test_protected_forged_ir_and_source_names_refused(self):
        for name in ('p0-web', 'broker', 'lanes', 'control', 'unit', 'namespace', 'platform-zero-host-broker',
                     'webservices-auto-update', 'Obelisks', 'a@x', 'foo*', '../escape'):
            ir = copy.deepcopy(self.ir); ir['services'][name] = {'placement': 'rootful', 'lifecycle': 'daemon'}
            put(self.bundle / 'stack.ir.json', ir)
            with self.subTest(name=name), self.assertRaises(n.Refused): n.inventory(self.bundle)
        put(self.bundle / 'stack.ir.json', self.ir)

    def test_unexpected_source_suffix_or_scope_refused(self):
        for filename in ('foreign.service', 'p0-web.container', 'webservices-extra.build',
                         'webservices-extra.network', 'webservices-extra.target', 'webservices-edge.container.d'):
            path = self.bundle / 'quadlet/rootful' / filename
            put(path, b'[Unit]\n')
            with self.subTest(filename=filename), self.assertRaises(n.Refused): n.inventory(self.bundle)
            path.unlink()
        (self.bundle / 'quadlet/rootless-lanes').mkdir()
        with self.assertRaises(n.Refused): n.inventory(self.bundle)

    def test_source_and_installed_symlinks_hardlinks_wrong_owner_modes(self):
        source = self.bundle / 'quadlet/rootful/webservices-edge.container'
        original = source.read_bytes(); other = self.base / 'other'; put(other, original)
        source.unlink(); source.symlink_to(other)
        with self.assertRaises((n.Refused, OSError)): n.inventory(self.bundle)
        source.unlink(); os.link(other, source)
        with self.assertRaises(n.Refused): n.inventory(self.bundle)
        source.unlink(); put(source, original)
        self.own(source, 781)
        with self.assertRaises(n.Refused): n.inventory(self.bundle)
        self.own(source, 0)
        for mode in (0o666, 0o755, 0o4755):
            source.chmod(mode)
            with self.assertRaises(n.Refused): n.inventory(self.bundle)
        source.chmod(0o644)
        path = self.install_file('quadlet/rootful/webservices-edge.container')
        path.unlink(); path.symlink_to(source)
        with self.assertRaises((n.Refused, OSError)): n.validate_installed(self.bundle)
        path.unlink(); os.link(source, path)
        with self.assertRaises(n.Refused): n.validate_installed(self.bundle)

    def test_ancestor_link_and_wrong_custody_even_when_destination_absent(self):
        directory = self.installed / 'rootful'; directory.mkdir()
        self.own(directory, 1000)
        with self.assertRaises(n.Refused): n.validate_installed(self.bundle)
        self.own(directory, 0); directory.chmod(0o777)
        with self.assertRaises(n.Refused): n.validate_installed(self.bundle)
        directory.chmod(0o755); directory.rmdir()
        target = self.base / 'target'; target.mkdir(); directory.symlink_to(target, target_is_directory=True)
        with self.assertRaises((n.Refused, OSError)): n.validate_installed(self.bundle)

    def test_actor_account_uid_and_home_drift(self):
        for uid, home in ((780, '/home/webservices-lab-apps'), (781, '/home/foreign')):
            with mock.patch.object(n.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_uid=uid, pw_dir=home)):
                with self.assertRaises(n.Refused): n.validate_installed(self.bundle)

    def test_actor_private_home_policy_no_broad_owner_exception(self):
        info = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=781)
        policy = self.pure_policy()
        for path in ('/home/webservices-lab-apps', '/home/webservices-lab-apps/.config',
                     '/home/webservices-lab-apps/.config/systemd/user', '/home/webservices-lab-apps/.config/containers/systemd'):
            policy(Path(path), info, (781, 'webservices-lab-apps'))
        for path in ('/home', '/home/foreign', '/sealed', '/home/webservices-lab-apps/foreign'):
            with self.assertRaises(n.Refused): policy(Path(path), info, (781, 'webservices-lab-apps'))

    def pure_policy(self):
        return self.original_policy

    def test_root_and_actor_destination_layout(self):
        self.assertEqual(self.real_destination('rootful', {'uid': 0, 'user': 'root'}, 'quadlet/rootful/webservices.target'), Path('/etc/systemd/system/webservices.target'))
        self.assertEqual(self.real_destination('rootful', {'uid': 0, 'user': 'root'}, 'quadlet/rootful/webservices-edge.container'), Path('/etc/containers/systemd/webservices-edge.container'))
        self.assertEqual(self.real_destination('rootless-apps', {'uid': 781, 'user': 'webservices-lab-apps'},
            'quadlet/rootless-apps/webservices.target'), Path('/home/webservices-lab-apps/.config/systemd/user/webservices.target'))

    def test_strict_json_bounds_path_escape(self):
        for raw in (b'{"backend":"podman","backend":"podman"}', b'{"backend":NaN}',
                    b'{"backend":"podman","invalid":1e9999}', b'\xff', b'[]'):
            put(self.bundle / 'bundle.json', raw)
            with self.assertRaises(n.Refused): n.inventory(self.bundle)
        put(self.bundle / 'bundle.json', {'backend': 'podman'})
        for path in ('relative', '/tmp/../escape', '//tmp/a', '/tmp//a'):
            with self.assertRaises(n.Refused): n.inventory(path)
        with mock.patch.object(n, 'LIMIT', 100):
            with self.assertRaises(n.Refused): n.inventory(self.bundle)

    def test_role_target_and_empty_domain_target_drift(self):
        source = self.bundle / 'quadlet/rootless-apps/webservices-keycloak-configure.container'
        body = source.read_bytes()
        for old, new in ((b'Type=oneshot', b'Type=notify'), (b'Restart=no', b'Restart=on-failure'),
                         (b'WantedBy=webservices-apps.target', b'WantedBy=webservices-core.target'),
                         (b'ContainerName=keycloak-configure', b'ContainerName=foreign')):
            put(source, body.replace(old, new))
            with self.assertRaises(n.Refused): n.inventory(self.bundle)
        put(source, body)
        source = self.bundle / 'quadlet/rootless-identity/webservices-apps.target'
        put(source, b'[Unit]\nWants=webservices-app.service\n')
        with self.assertRaises(n.Refused): n.inventory(self.bundle)
        source.unlink()
        with self.assertRaises(n.Refused): n.inventory(self.bundle)

    def test_target_installation_cannot_enable_foreign_boot_trigger(self):
        path = self.bundle / 'quadlet/rootful/webservices.target'
        original = path.read_bytes()
        put(path, original.replace(b'WantedBy=multi-user.target', b'WantedBy=p0-web.target'))
        with self.assertRaises(n.Refused): n.inventory(self.bundle)
        put(path, original)
        path = self.bundle / 'quadlet/rootless-apps/webservices-apps.target'
        original = path.read_bytes()
        put(path, original.replace(b'PartOf=webservices.target', b'PartOf=foreign.target'))
        with self.assertRaises(n.Refused): n.inventory(self.bundle)

    def test_foreign_dependencies_aliases_and_duplicate_identity(self):
        path = self.bundle / 'quadlet/rootful/webservices-edge.container'; original = path.read_bytes()
        for extra in (b'[Unit]\nWants=p0-web.service\n', b'[Unit]\nPartOf=platform-zero-host-broker.service\n',
                      b'[Install]\nAlias=p0-web.service\n', b'[Container]\nContainerName=edge\n'):
            put(path, original + extra)
            with self.assertRaises(n.Refused): n.inventory(self.bundle)

    def test_whole_required_graph_must_be_nonempty(self):
        for service in self.ir['services'].values(): service['lifecycle'] = 'on-demand'
        put(self.bundle / 'stack.ir.json', self.ir)
        with self.assertRaises(n.Refused): n.inventory(self.bundle)

    def test_missing_account_only_valid_for_absent_actor_destinations(self):
        with mock.patch.object(n.pwd, 'getpwnam', side_effect=KeyError):
            self.assertGreater(n.validate_installed(self.bundle)['absent'], 0)
            self.install_file('quadlet/rootless-apps/webservices-app.container')
            with self.assertRaises(n.Refused): n.validate_installed(self.bundle)

    def test_generated_unit_collision_refused(self):
        # A container named bootstrap-build would collide with the exact .build
        # producer ID. No prefix-based selection may silently merge them.
        self.ir['services']['bootstrap-build'] = dict(self.ir['services']['app'])
        self.domains['domains'][0]['services'].append('bootstrap-build')
        self.domains['domains'][0]['persistentServices'].append('bootstrap-build')
        put(self.bundle / 'stack.ir.json', self.ir); put(self.bundle / 'podman-domains.json', self.domains)
        put(self.bundle / 'quadlet/rootless-apps/webservices-bootstrap-build.container',
            b'[Container]\nContainerName=bootstrap-build\nImage=sha256:' + b'a' * 64 + b'\n[Install]\nWantedBy=webservices-apps.target\n')
        target = self.bundle / 'quadlet/rootless-apps/webservices-apps.target'
        target.write_bytes(target.read_bytes().replace(b'Wants=', b'Wants=webservices-bootstrap-build.service '))
        with self.assertRaises(n.Refused): n.inventory(self.bundle)

    def test_network_build_image_and_declared_role_drift(self):
        for relative, replacement in (
            ('quadlet/rootful/webservices-default.network', b'[Network]\nNetworkName=foreign\n'),
            ('quadlet/rootless-apps/webservices-bootstrap.build', b'[Build]\nImageTag=foreign\n'),
            ('quadlet/rootless-apps/webservices-app.container', b'[Container]\nContainerName=app\nImage=foreign\n[Install]\nWantedBy=webservices-apps.target\n')):
            path = self.bundle / relative; original = path.read_bytes(); put(path, replacement)
            with self.assertRaises(n.Refused): n.inventory(self.bundle)
            put(path, original)
        self.domains['domains'][0]['persistentServices'].append('keycloak-configure')
        put(self.bundle / 'podman-domains.json', self.domains)
        with self.assertRaises(n.Refused): n.inventory(self.bundle)

    def test_unfrozen_on_demand_build_and_registry_image_qualification(self):
        del self.ir['services']['bootstrap']['frozenBuildImage']
        put(self.bundle / 'stack.ir.json', self.ir)
        path = self.bundle / 'quadlet/rootless-apps/webservices-bootstrap.container'
        path.write_bytes(path.read_bytes().replace(('sha256:' + 'a' * 64).encode(), b'webservices-bootstrap.build'))
        plan = n.inventory(self.bundle)
        self.assertIn('webservices-bootstrap-build.service', plan['rootless-apps']['units'])
        self.assertNotIn('webservices-bootstrap.service', plan['rootless-apps']['persistent'])
        path = self.bundle / 'quadlet/rootful/webservices-edge.container'; body = path.read_bytes()
        for ir_image, quadlet_image in (('alpine:3', 'docker.io/library/alpine:3'),
                                       ('example/app:pin', 'docker.io/example/app:pin'),
                                       ('localhost/app:pin', 'localhost/app:pin'),
                                       ('registry.example/app@sha256:' + 'b' * 64, 'registry.example/app@sha256:' + 'b' * 64)):
            self.ir['services']['edge']['image'] = ir_image
            put(self.bundle / 'stack.ir.json', self.ir)
            put(path, body.replace(('sha256:' + 'a' * 64).encode(), quadlet_image.encode()))
            n.inventory(self.bundle)

    def test_source_ancestor_symlink_and_metadata_hardlink_refused(self):
        directory = self.bundle / 'quadlet/rootful'
        other = self.bundle / 'moved'; directory.rename(other); directory.symlink_to(other, target_is_directory=True)
        with self.assertRaises((n.Refused, OSError)): n.inventory(self.bundle)
        directory.unlink(); other.rename(directory)
        os.link(self.bundle / 'bundle.json', self.base / 'metadata-hardlink')
        with self.assertRaises(n.Refused): n.inventory(self.bundle)

    def test_inventory_detects_drift_within_source_sweep(self):
        real = n.read_file; reads = [0]
        source = self.bundle / 'quadlet/rootful/webservices-edge.container'
        def reader(path, **kwargs):
            result = real(path, **kwargs)
            if Path(path) == source:
                reads[0] += 1
                if reads[0] == 1: source.write_bytes(source.read_bytes() + b'# changed after read\n')
            return result
        with mock.patch.object(n, 'read_file', side_effect=reader), self.assertRaises(n.Refused):
            n.inventory(self.bundle)

    def test_no_source_or_destination_mutation(self):
        selected = self.install_file('quadlet/rootless-apps/webservices-app.container')
        paths = [p for p in self.base.rglob('*') if p.is_file()]
        before = {p: (p.read_bytes(), p.stat().st_mode) for p in paths}
        n.inventory(self.bundle); n.selection(self.bundle); n.validate_installed(self.bundle)
        self.assertEqual(before, {p: (p.read_bytes(), p.stat().st_mode) for p in paths})
        self.assertEqual(set(paths), {p for p in self.base.rglob('*') if p.is_file()})

    def test_installed_destination_change_during_sweep_refused(self):
        path = self.install_file('quadlet/rootful/webservices-edge.container')
        real = n.read_file; changed = [False]
        def reader(target, **kwargs):
            result = real(target, **kwargs)
            if Path(target) == path and not changed[0]:
                changed[0] = True
                path.write_bytes(b'foreign concurrent replacement')
            return result
        with mock.patch.object(n, 'read_file', side_effect=reader), self.assertRaises(n.Refused):
            n.validate_installed(self.bundle)

    def test_nonselection_ir_changes_are_still_hash_bound(self):
        before = n.selection(self.bundle)
        self.ir['services']['app']['command'] = ['synthetic', 'new-command']
        put(self.bundle / 'stack.ir.json', self.ir)
        after = n.selection(self.bundle)
        self.assertEqual(before['scopes'], after['scopes'])
        self.assertNotEqual(before['sources']['candidate']['inputs'], after['sources']['candidate']['inputs'])

    def test_installed_source_changes_during_sweep_fail_closed(self):
        real = n.read_file; changed = [False]
        def reader(path, **kwargs):
            result = real(path, **kwargs)
            if Path(path).is_relative_to(self.installed) and not changed[0]:
                changed[0] = True
                source = self.bundle / 'quadlet/rootful/webservices-edge.container'
                source.write_bytes(source.read_bytes() + b'# concurrent drift\n')
            return result
        with mock.patch.object(n, 'read_file', side_effect=reader), self.assertRaises(n.Refused):
            n.validate_installed(self.bundle)


if __name__ == '__main__':
    unittest.main()
