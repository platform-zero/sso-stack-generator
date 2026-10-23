#!/usr/bin/env python3
"""Mock/source proof ONLY. No manager/container/network/native installer calls."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/verify-native-readiness.py'
spec = importlib.util.spec_from_file_location('native_readiness_under_test', SOURCE)
r = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = r
spec.loader.exec_module(r)


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def fixture():
    services = {
        'edge': {'lifecycle': 'daemon', 'placement': 'rootful', 'target': 'core',
                 'health': {'test': ['CMD', 'true']}},
        'keycloak-configure': {'lifecycle': 'oneshot', 'placement': 'rootless', 'rootlessDomain': 'apps'},
        'firefly-identity-check': {'lifecycle': 'oneshot', 'placement': 'rootless', 'rootlessDomain': 'apps'},
        'app': {'lifecycle': 'daemon', 'placement': 'rootless', 'rootlessDomain': 'apps', 'build': {}},
        'client': {'lifecycle': 'on-demand', 'placement': 'rootless', 'rootlessDomain': 'apps'},
        'managed-client': {'lifecycle': 'on-demand', 'placement': 'rootless',
                           'rootlessDomain': 'apps', 'quadletManaged': True},
    }
    for service in services.values():
        service['image'] = 'sha256:' + 'a' * 64
    services['app']['frozenBuildImage'] = services['app']['image']
    domains = {'schemaVersion': 1, 'deploymentMode': 'standalone', 'installerStateRoot': '/sealed',
               'storageScope': {'root': '/scope', 'dataClass': 'synthetic'},
               'domains': [
                   {'name': 'apps', 'user': 'svc-apps', 'uid': 21001,
                    'services': ['keycloak-configure', 'firefly-identity-check', 'app', 'client', 'managed-client'],
                    'persistentServices': ['app']},
                   {'name': 'empty', 'user': 'svc-empty', 'uid': 21002,
                    'services': [], 'persistentServices': []}]}
    rendered = {}
    for name, service in services.items():
        if name == 'client': continue
        scope = 'rootful' if service['placement'] == 'rootful' else 'rootless-apps'
        target = service.get('target', 'apps')
        role = service['lifecycle']
        body = '[Container]\nContainerName=' + name + '\nImage=sha256:' + 'a' * 64 + '\n'
        if service.get('health'): body += 'HealthCmd=["true"]\n'
        body += '[Service]\n'
        if role == 'oneshot': body += 'Type=oneshot\nRemainAfterExit=yes\nRestart=no\n'
        body += '[Install]\n'
        if role != 'on-demand': body += 'WantedBy=webservices-' + target + '.target\n'
        rendered['quadlet/' + scope + '/webservices-' + name + '.container'] = body.encode()
        if 'build' in service:
            rendered['quadlet/' + scope + '/webservices-' + name + '.build'] = b'[Build]\nImageTag=localhost/build\n'
    for scope in ('rootful', 'rootless-apps', 'rootless-empty'):
        for target in ('core', 'apps', 'observability'):
            names = []
            for name, service in services.items():
                s = 'rootful' if service['placement'] == 'rootful' else 'rootless-apps'
                if s == scope and service.get('target', 'apps') == target and service['lifecycle'] != 'on-demand':
                    names.append('webservices-' + name + '.service')
            rendered['quadlet/' + scope + '/webservices-' + target + '.target'] = (
                '[Unit]\n' + ('Wants=' + ' '.join(names) + '\n' if names else '')).encode()
        rendered['quadlet/' + scope + '/webservices.target'] = (
            b'[Unit]\nWants=webservices-core.target webservices-apps.target webservices-observability.target\n')
    rendered['quadlet/rootful/webservices-default.network'] = b'[Network]\nNetworkName=webservices_default\n'
    return {'schemaVersion': 1, 'services': services}, domains, rendered


def observations(plan):
    units = {}; containers = {}
    for i, unit in enumerate(plan, 1):
        oneshot = unit.role == 'oneshot'
        props = dict.fromkeys(r.PROPERTIES, '')
        props.update(Id=unit.name, LoadState='loaded', ActiveState='active',
                     SubState='exited' if oneshot else 'running', Type='oneshot' if oneshot else 'notify',
                     Result='success', Job='', InvocationID=f'{i:032x}',
                     ExecMainStartTimestampMonotonic='2000000',
                     ExecMainExitTimestampMonotonic='2500000' if oneshot else '0',
                     ActiveEnterTimestampMonotonic='2600000', NRestarts='0',
                     ExecMainCode='1' if oneshot else '0', ExecMainStatus='0',
                     ConditionResult='yes', AssertResult='yes', MainPID='0' if oneshot else str(100 + i),
                     SourcePath=unit.source, FragmentPath=unit.name,
                     ControlGroup='' if oneshot else '/system.slice/' + unit.name)
        units.setdefault(unit.scope, {})[unit.name] = props
        if not oneshot:
            containers.setdefault(unit.scope, {})[unit.container] = {
                'name': unit.container, 'id': f'{i:064x}', 'unit': unit.name, 'running': True,
                'restarting': False, 'dead': False, 'status': 'running',
                'healthConfigured': unit.health, 'health': 'healthy' if unit.health else '',
                'restartCount': 0, 'startedAt': '2026-01-01T00:00:00Z', 'pid': 300 + i,
                'conmonPid': 100 + i, 'image': unit.image}
    return {'units': units, 'containers': containers,
            'binding': {'cas': 'sealed-cas', 'receipt': 'starting', 'current': 'release-1',
                        'marker': 'scope-1', 'hashes': 'sealed'}}


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.ir, self.domains, self.rendered = fixture()
        self.plan = r.derive_plan(self.ir, self.domains, self.rendered)
        self.data = observations(self.plan)
        self.time = 10.0
        self.calls = []
        self.tick = 0
        self.mutate = lambda: None

    def run_graph(self, **changes):
        def query(kind, scope, names, remaining):
            self.calls.append((kind, scope, names, remaining))
            self.assertGreater(remaining, 0)
            return copy.deepcopy(self.data[kind][scope])
        def sleep(seconds):
            self.time += seconds; self.tick += 1; self.mutate()
        args = dict(query_units=lambda s, n, t: query('units', s, n, t),
                    query_containers=lambda s, n, t: query('containers', s, n, t),
                    recheck=lambda: copy.deepcopy(self.data['binding']),
                    source_matches=lambda u, s, f: s == u.source and f == u.name,
                    runtime_matches=lambda u, p, c: c['conmonPid'] == int(p['MainPID']) and c['image'] == u.image,
                    attempt_start_us=1_000_000, stable_seconds=2, timeout_seconds=10,
                    poll_seconds=1, clock=lambda: self.time, sleep=sleep)
        args.update(changes)
        return r.verify_graph(self.plan, **args)

    def test_whole_graph_success_excludes_clients_build_and_empty_domain_queries(self):
        result = self.run_graph()
        self.assertEqual(result['units'], 4)
        self.assertEqual(result['samples'], 3)
        self.assertFalse(result['applicationAcceptance'])
        self.assertGreaterEqual(result['stableSeconds'], 2)
        self.assertEqual({c[1] for c in self.calls}, {'rootful', 'rootless-apps'})
        for kind, scope, names, remaining in self.calls:
            self.assertNotIn('webservices-app-build.service', names)
            self.assertNotIn('webservices-client.service', names)
            self.assertNotIn('webservices-managed-client.service', names)
            self.assertTrue(all('*' not in n for n in names))

    def test_review_active_target_with_both_failed_oneshots_refused(self):
        for name in ('keycloak-configure', 'firefly-identity-check'):
            self.data['units']['rootless-apps']['webservices-' + name + '.service'].update(
                ActiveState='failed', Result='exit-code')
        with self.assertRaises(r.Refused): self.run_graph()

    def test_review_false_success_properties(self):
        original = copy.deepcopy(self.data)
        cases = [('Result', 'exit-code'), ('Job', '23'), ('Job', '23 /job/23'),
                 ('LoadState', 'not-found'), ('LoadState', 'masked'), ('LoadState', 'error'),
                 ('ActiveState', 'inactive'), ('ActiveState', 'failed'),
                 ('SubState', 'auto-restart'), ('SubState', 'start'), ('Type', 'oneshot'),
                 ('InvocationID', ''), ('InvocationID', '0' * 32), ('InvocationID', 'g' * 32),
                 ('ExecMainStartTimestampMonotonic', '0'), ('ExecMainStartTimestampMonotonic', '999999999'),
                 ('ActiveEnterTimestampMonotonic', '999999999'), ('ExecMainExitTimestampMonotonic', '12'),
                 ('ExecMainStatus', '1'), ('ExecMainCode', '2'), ('MainPID', '0'),
                 ('ConditionResult', 'no'), ('AssertResult', 'no'),
                 ('DropInPaths', '/foreign/override.conf'), ('ControlGroup', '')]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                self.data = copy.deepcopy(original)
                self.data['units']['rootful']['webservices-edge.service'][key] = value
                with self.assertRaises(r.Refused): self.run_graph()

    def test_review_never_invoked_skipped_stale_oneshot(self):
        original = copy.deepcopy(self.data)
        cases = [('ActiveState', 'inactive'), ('SubState', 'dead'), ('ExecMainCode', '0'),
                 ('ExecMainStatus', '1'), ('ExecMainStartTimestampMonotonic', '0'),
                 ('ExecMainStartTimestampMonotonic', '999999'),
                 ('ExecMainExitTimestampMonotonic', '0'), ('ExecMainExitTimestampMonotonic', '1999999'),
                 ('ExecMainExitTimestampMonotonic', '999999999'),
                 ('ActiveEnterTimestampMonotonic', '1'), ('InvocationID', ''),
                 ('ConditionResult', 'no'), ('AssertResult', 'no'), ('MainPID', '2'),
                 ('NRestarts', '1'), ('Result', 'exit-code'), ('Job', '18')]
        for key, value in cases:
            with self.subTest(key=key):
                self.data = copy.deepcopy(original)
                self.data['units']['rootless-apps']['webservices-keycloak-configure.service'][key] = value
                with self.assertRaises(r.Refused): self.run_graph()

    def test_missing_extra_or_partial_unit_inventory_refused(self):
        original = copy.deepcopy(self.data)
        for mutation in ('empty', 'missing', 'extra', 'property'):
            with self.subTest(mutation=mutation):
                self.data = copy.deepcopy(original)
                rows = self.data['units']['rootful']
                if mutation == 'empty': rows.clear()
                if mutation == 'missing': del rows['webservices-edge.service']
                if mutation == 'extra': rows['webservices-unselected.service'] = next(iter(rows.values()))
                if mutation == 'property': del rows['webservices-edge.service']['Result']
                with self.assertRaises(r.Refused): self.run_graph()

    def test_review_actual_health_required(self):
        for health in ('unhealthy', 'starting', '', None):
            with self.subTest(health=health):
                self.data['containers']['rootful']['edge']['health'] = health
                with self.assertRaises(r.Refused): self.run_graph()

    def test_container_identity_owner_image_and_state_failures(self):
        original = copy.deepcopy(self.data)
        cases = [('name', 'unselected'), ('unit', 'webservices-other.service'), ('id', 'short'),
                 ('running', False), ('restarting', True), ('dead', True), ('status', 'exited'),
                 ('healthConfigured', False), ('healthConfigured', 'true'), ('restartCount', -1),
                 ('pid', 0), ('conmonPid', 99999), ('image', 'sha256:' + 'b' * 64), ('startedAt', '')]
        for key, value in cases:
            with self.subTest(key=key):
                self.data = copy.deepcopy(original)
                self.data['containers']['rootful']['edge'][key] = value
                with self.assertRaises(r.Refused): self.run_graph()

    def test_missing_extra_and_full_inspect_container_refused(self):
        original = copy.deepcopy(self.data)
        for mutation in ('missing', 'extra', 'env'):
            with self.subTest(mutation=mutation):
                self.data = copy.deepcopy(original)
                rows = self.data['containers']['rootful']
                if mutation == 'missing': rows.clear()
                if mutation == 'extra': rows['unselected'] = rows['edge']
                if mutation == 'env': rows['edge']['Env'] = ['DO_NOT_PRINT=sentinel']
                with self.assertRaises(r.Refused) as error: self.run_graph()
                self.assertNotIn('sentinel', str(error.exception))

    def test_review_cross_domain_failure_during_stabilization(self):
        self.mutate = lambda: self.data['units']['rootful']['webservices-edge.service'].update(Result='exit-code')
        with self.assertRaises(r.Refused): self.run_graph()
        self.assertEqual(self.tick, 1)

    def test_failure_while_later_domain_is_observed(self):
        calls = [0]
        def containers(scope, names, left):
            if scope == 'rootless-apps':
                calls[0] += 1
                self.data['units']['rootful']['webservices-edge.service']['Result'] = 'exit-code'
            return self.data['containers'][scope]
        with self.assertRaises(r.Refused): self.run_graph(query_containers=containers)
        self.assertGreaterEqual(calls[0], 1)

    def test_final_sample_closes_earlier_domain_after_later_query(self):
        def containers(scope, names, left):
            if self.tick == 2 and scope == 'rootless-apps':
                self.data['units']['rootful']['webservices-edge.service']['Result'] = 'exit-code'
            return copy.deepcopy(self.data['containers'][scope])
        with self.assertRaises(r.Refused): self.run_graph(query_containers=containers)
        self.assertEqual(self.tick, 2)

    def test_late_unhealthy_rootful_container_not_hidden_by_rootless_stabilization(self):
        def containers(scope, names, left):
            if self.tick == 2 and scope == 'rootless-apps':
                self.data['containers']['rootful']['edge']['health'] = 'unhealthy'
            return copy.deepcopy(self.data['containers'][scope])
        with self.assertRaises(r.Refused): self.run_graph(query_containers=containers)

    def test_failure_evidence_is_unchanged_no_retry_or_reset(self):
        self.data['units']['rootful']['webservices-edge.service']['Result'] = 'exit-code'
        before = copy.deepcopy(self.data)
        with self.assertRaises(r.Refused): self.run_graph()
        self.assertEqual(self.data, before)
        self.assertEqual(self.tick, 0)

    def test_review_healthy_looking_restarts_or_identity_changes_fail(self):
        original = copy.deepcopy(self.data)
        mutations = [lambda: self.data['units']['rootful']['webservices-edge.service'].update(NRestarts='1'),
                     lambda: self.data['units']['rootful']['webservices-edge.service'].update(InvocationID='f' * 32),
                     lambda: self.data['units']['rootless-apps']['webservices-keycloak-configure.service'].update(InvocationID='f' * 32),
                     lambda: self.data['containers']['rootful']['edge'].update(restartCount=1),
                     lambda: self.data['containers']['rootful']['edge'].update(id='f' * 64),
                     lambda: self.data['containers']['rootful']['edge'].update(startedAt='changed')]
        for i, mutation in enumerate(mutations):
            with self.subTest(mutation=i):
                self.data = copy.deepcopy(original); self.mutate = mutation
                with self.assertRaises(r.Refused): self.run_graph()

    def test_review_current_marker_hash_cas_receipt_drift(self):
        for field in ('cas', 'receipt', 'current', 'marker', 'hashes'):
            with self.subTest(field=field):
                self.data = observations(self.plan)
                self.mutate = lambda: self.data['binding'].update({field: 'drift'})
                with self.assertRaises(r.Refused): self.run_graph()

    def test_final_recheck_is_mandatory(self):
        count = [0]
        def recheck():
            count[0] += 1
            # Initial + pre/post for three samples = 7; final return gate = 8.
            return {'cas': 'changed' if count[0] >= 8 else 'same'}
        with self.assertRaises(r.Refused): self.run_graph(recheck=recheck)
        self.assertEqual(count[0], 8)

    def test_source_and_runtime_authority_callbacks_fail_closed(self):
        for key in ('source_matches', 'runtime_matches'):
            for result in (False, None, 'truthy-is-not-proof'):
                with self.subTest(key=key, result=result):
                    with self.assertRaises(r.Refused): self.run_graph(**{key: lambda *a: result})

    def test_bounds_and_slow_queries(self):
        for args in ({'stable_seconds': 0}, {'timeout_seconds': 121}, {'poll_seconds': 0},
                     {'stable_seconds': 10}, {'stable_seconds': float('nan')},
                     {'attempt_start_us': 0}, {'attempt_start_us': 999999999}):
            with self.subTest(args=args):
                with self.assertRaises(r.Refused): self.run_graph(**args)
        def slow(scope, names, remaining):
            self.time += 20
            return self.data['units'][scope]
        with self.assertRaises(r.Refused): self.run_graph(query_units=slow)

    def test_no_mutating_or_host_api_import(self):
        # Main's query owner is injected; importing and exercising this module
        # cannot reach subprocess/systemctl/podman or create a new root executor.
        self.assertNotIn('subprocess', vars(r))
        self.assertNotIn('fcntl', vars(r))
        self.assertNotIn('socket', vars(r))


class PlanTests(unittest.TestCase):
    def setUp(self): self.ir, self.domains, self.rendered = fixture()
    def derive(self): return r.derive_plan(self.ir, self.domains, self.rendered)

    def test_sealed_empty_targets_are_explicit(self):
        self.assertEqual(len(self.derive()), 4)
        del self.rendered['quadlet/rootless-empty/webservices-apps.target']
        with self.assertRaises(r.Refused): self.derive()

    def test_empty_ir_or_targets_never_succeed(self):
        self.ir['services'] = {}
        with self.assertRaises(r.Refused): self.derive()

    def test_missing_and_unselected_rendered_workloads(self):
        for name in ('webservices-protected.service', 'webservices-protected.container',
                     'webservices-extra.target', 'webservices-extra.build'):
            with self.subTest(name=name):
                self.ir, self.domains, self.rendered = fixture()
                self.rendered['quadlet/rootful/' + name] = b'[Unit]\n'
                with self.assertRaises(r.Refused): self.derive()

    def test_target_mismatch_duplicate_prefix_and_escape(self):
        original = copy.deepcopy(self.rendered)
        for text in ('Wants=webservices-unselected.service', 'Wants=webservices-*.service',
                     'Wants=webservices-edge.service webservices-edge.service', 'Wants='):
            with self.subTest(text=text):
                self.rendered = copy.deepcopy(original)
                self.rendered['quadlet/rootful/webservices-core.target'] = ('[Unit]\n' + text).encode()
                with self.assertRaises(r.Refused): self.derive()
        self.rendered = original
        self.rendered['quadlet/rootful/../../escape.network'] = b'[Network]\nNetworkName=escape\n'
        with self.assertRaises(r.Refused): self.derive()

    def test_health_and_container_identity_disagreement(self):
        path = 'quadlet/rootful/webservices-edge.container'; original = self.rendered[path]
        for body in (original.replace(b'ContainerName=edge', b'ContainerName=other'),
                     original.replace(b'HealthCmd=["true"]\n', b''),
                     original + b'[Container]\nContainerName=edge\n'):
            with self.subTest(body=body):
                self.rendered[path] = body
                with self.assertRaises(r.Refused): self.derive()

    def test_domain_selection_identity_disagreement(self):
        for key, value in [('services', []), ('persistentServices', []), ('uid', 0), ('user', 'bad user')]:
            with self.subTest(key=key):
                self.ir, self.domains, self.rendered = fixture()
                self.domains['domains'][0][key] = value
                with self.assertRaises(r.Refused): self.derive()

    def test_unknown_role_and_manager_no_fallback(self):
        for changes in ({'lifecycle': 'producer'}, {'placement': 'unknown'},
                        {'placement': 'rootless', 'rootlessDomain': 'missing'}):
            with self.subTest(changes=changes):
                self.ir, self.domains, self.rendered = fixture()
                self.ir['services']['edge'].update(changes)
                with self.assertRaises(r.Refused): self.derive()

    def test_rendered_image_mismatch_and_build_producer_identity(self):
        path = 'quadlet/rootful/webservices-edge.container'
        self.rendered[path] = self.rendered[path].replace(('sha256:' + 'a' * 64).encode(),
                                                        ('sha256:' + 'b' * 64).encode())
        with self.assertRaises(r.Refused): self.derive()
        self.ir, self.domains, self.rendered = fixture()
        del self.ir['services']['app']['frozenBuildImage']
        path = 'quadlet/rootless-apps/webservices-app.container'
        self.rendered[path] = self.rendered[path].replace(('sha256:' + 'a' * 64).encode(), b'webservices-app.build')
        plan = self.derive()
        self.assertEqual(next(u.image for u in plan if u.container == 'app'), 'webservices-app.build')
        self.assertFalse(any(u.name.endswith('-build.service') for u in plan))

    def test_required_oneshot_not_build_producer(self):
        path = 'quadlet/rootless-apps/webservices-keycloak-configure.container'
        self.rendered[path] = self.rendered[path].replace(b'RemainAfterExit=yes', b'RemainAfterExit=no')
        with self.assertRaises(r.Refused): self.derive()


class QueriesTests(unittest.TestCase):
    def setUp(self):
        self.plan = r.derive_plan(*fixture()); self.data = observations(self.plan); self.calls = []
        self.commands = {'rootful': (['mock-systemctl'], ['mock-podman', '--root=/selected/root']),
                         'rootless-apps': (['mock-user-systemctl', '--user'],
                                           ['mock-user-podman', '--root=/selected/apps'])}
    def runner(self, args, timeout):
        self.calls.append((args, timeout))
        scope = 'rootless-apps' if args[0].startswith('mock-user') else 'rootful'
        if 'show' in args:
            text = '\n\n'.join('\n'.join(k + '=' + v for k, v in row.items())
                               for row in self.data['units'][scope].values())
        else:
            text = '\n'.join(json.dumps(row) for row in self.data['containers'][scope].values())
        return types.SimpleNamespace(returncode=0, stdout=text)
    def test_exact_bounded_queries_no_enumeration(self):
        queries = r.SelectedQueries(self.plan, self.commands, self.runner)
        for scope in self.commands:
            units = tuple(u.name for u in self.plan if u.scope == scope)
            containers = tuple(u.container for u in self.plan if u.scope == scope and u.role == 'daemon')
            self.assertEqual(queries.units(scope, units, 2.5), self.data['units'][scope])
            self.assertEqual(queries.containers(scope, containers, 2.5), self.data['containers'][scope])
        for command, timeout in self.calls:
            self.assertEqual(timeout, 2.5)
            self.assertIn('--', command)
            self.assertFalse(any('*' in arg for arg in command))
            self.assertNotIn('list-units', command)
            self.assertNotIn('ps', command)
            self.assertNotIn('Env', r.CONTAINER_FORMAT)
            self.assertNotIn('.Log', r.CONTAINER_FORMAT)
    def test_query_error_and_timeout_no_raw_output(self):
        for runner in (lambda *a, **k: types.SimpleNamespace(returncode=1, stdout='PRIVATE_SENTINEL'),
                       mock.Mock(side_effect=TimeoutError('PRIVATE_SENTINEL'))):
            queries = r.SelectedQueries(self.plan, self.commands, runner)
            with self.assertRaises(r.Refused) as error:
                queries.units('rootful', ('webservices-edge.service',), 2)
            self.assertNotIn('PRIVATE_SENTINEL', str(error.exception))
    def test_no_unselected_query_even_with_prefixed_name(self):
        queries = r.SelectedQueries(self.plan, self.commands, self.runner)
        for name in ('webservices-protected.service', 'webservices-*.service'):
            with self.assertRaises(r.Refused): queries.units('rootful', (name,), 2)
        self.assertEqual(self.calls, [])
    def test_show_missing_duplicate_or_extra_properties(self):
        row = self.data['units']['rootful']['webservices-edge.service']
        text = '\n'.join(k + '=' + v for k, v in row.items())
        for bad in (text + '\nResult=success', text + '\n\n' + text,
                    text.replace('Result=success\n', ''), text + '\nUnexpected=sentinel'):
            with self.subTest(case=bad[-30:]):
                with self.assertRaises(r.Refused): r.parse_show(bad)


class JournalTests(unittest.TestCase):
    def setUp(self):
        ir, domains, rendered = fixture()
        self.root = Path('/sealed'); self.release = self.root / 'releases/r1'
        self.journal = types.SimpleNamespace(CORE_INPUTS=('bundle.json', 'stack.ir.json', 'source-provenance.json'),
                                            PINNED_INPUTS=('podman-domains.json', 'site/manifest.json', 'absent.json'))
        self.files = {str(self.release / 'stack.ir.json'): encoded(ir),
                      str(self.release / 'podman-domains.json'): encoded(domains),
                      str(self.release / 'bundle.json'): b'{}',
                      str(self.release / 'source-provenance.json'): b'{}',
                      str(self.release / 'site/manifest.json'): encoded({'deploymentMode': 'standalone',
                          'installerStateRoot': str(self.root), 'storageScope': domains['storageScope']}),
                      '/scope/.stack-installation.json': b'{"mock":"marker"}'}
        for name, body in rendered.items(): self.files[str(self.release / name)] = body
        pins = {name: r.sha(self.files[str(self.release / name)])
                for name in self.journal.CORE_INPUTS + self.journal.PINNED_INPUTS if name != 'absent.json'}
        pins['absent.json'] = None
        self.value = {'schemaVersion': 1, 'phase': 'starting', 'release': str(self.release), 'inputs': pins,
                      'readiness': {'bootId': 'mock-boot', 'startMonotonicUSec': 1_000_000,
                                    'renderedInputs': {n: r.sha(b) for n, b in rendered.items()}}}
        self.paths = list(rendered); self.locked = True; self.pointer = True
        self.storage = {'markerSha256': r.sha(self.files['/scope/.stack-installation.json']), 'scope': '/scope'}
        self.seal()
    def seal(self):
        body = encoded(self.value)
        self.files[str(self.root / '.install-intent.json')] = body
        self.files[str(self.release / 'installation-receipt.json')] = body
        self.cas = r.sha(body)
    def reader(self, path, **kwargs):
        try: return self.files[str(path)]
        except KeyError: raise FileNotFoundError from None
    def selection(self):
        return r.JournalSelection(self.root, self.cas, journal=self.journal,
                                  storage_binding=lambda _: self.storage,
                                  pointer_matches=lambda *a: self.pointer,
                                  assert_locked=lambda: self.locked,
                                  inventory_paths=lambda _: self.paths,
                                  boot_id=lambda: 'mock-boot', reader=self.reader)
    def test_exact_starting_receipt_selection(self):
        owner = self.selection(); value = owner.snapshot()
        self.assertEqual(len(owner.plan), 4)
        self.assertEqual(owner.attempt_start_us, 1_000_000)
        self.assertEqual(value, owner.snapshot())
    def test_old_unsealed_receipt_refused(self):
        del self.value['readiness']; self.seal()
        with self.assertRaises(r.Refused): self.selection().snapshot()
    def test_review_partial_receipt_intent_write_is_not_admission(self):
        for body in (encoded(dict(self.value, phase='active')), encoded(self.value) + b' '):
            with self.subTest(receipt=body[-20:]):
                self.files[str(self.release / 'installation-receipt.json')] = body
                with self.assertRaises(r.Refused): self.selection().snapshot()
    def test_receipt_cas_current_lock_boot_and_marker_failures(self):
        for name in ('cas', 'pointer', 'lock', 'boot', 'marker'):
            with self.subTest(name=name):
                self.setUp()
                if name == 'cas': self.cas = '0' * 64
                if name == 'pointer': self.pointer = False
                if name == 'lock': self.locked = False
                if name == 'boot': self.value['readiness']['bootId'] = 'old-boot'; self.seal()
                if name == 'marker': self.storage = {}
                with self.assertRaises(r.Refused): self.selection().snapshot()
    def test_rendered_and_input_hash_and_inventory_drift(self):
        for name in ('input', 'rendered', 'inventory', 'absent', 'marker-hash'):
            with self.subTest(name=name):
                self.setUp()
                if name == 'input': self.files[str(self.release / 'stack.ir.json')] += b' '
                if name == 'rendered': self.files[str(self.release / self.paths[0])] += b'# drift\n'
                if name == 'inventory': self.paths.append('quadlet/rootful/webservices-unselected.container')
                if name == 'absent': self.files[str(self.release / 'absent.json')] = b'appeared'
                if name == 'marker-hash': self.files['/scope/.stack-installation.json'] += b' '
                with self.assertRaises(r.Refused): self.selection().snapshot()
    def test_receipt_drift_during_last_read(self):
        selection = self.selection(); count = [0]
        def reader(path, **kwargs):
            body = self.reader(path, **kwargs)
            if path.name == 'installation-receipt.json':
                count[0] += 1
                if count[0] == 2: return body + b' '
            return body
        selection.reader = reader
        with self.assertRaises(r.Refused): selection.snapshot()
    def test_rendered_pin_escape_and_duplicate_inventory_refused(self):
        for case in ('escape', 'duplicate'):
            with self.subTest(case=case):
                self.setUp()
                if case == 'escape':
                    name = 'quadlet/rootful/../../escape.container'
                    self.value['readiness']['renderedInputs'][name] = 'a' * 64
                    self.paths.append(name)
                    self.seal()
                else:
                    self.paths.append(self.paths[0])
                with self.assertRaises(r.Refused): self.selection().snapshot()

    def test_no_phase_or_root_escape(self):
        for change in ({'phase': 'active'}, {'phase': 'failed'}, {'release': '/unrelated/releases/r1'}):
            with self.subTest(change=change):
                self.setUp(); self.value.update(change); self.seal()
                with self.assertRaises(r.Refused): self.selection().snapshot()
    def test_duplicate_authority_json_rejected(self):
        with self.assertRaises(r.Refused): r.strict(b'{"phase":"starting","phase":"active"}')


class FilesystemTests(unittest.TestCase):
    """Real isolated temp inodes; root path/ownership are simulated, never chown."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-readiness-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'sealed').mkdir(mode=0o700)
        (self.root / 'sealed/file').write_bytes(b'sealed')
        (self.root / 'sealed/file').chmod(0o600)
        real_open = os.open; real_fstat = os.fstat
        def open_fake(path, flags, *args, **kwargs):
            return real_open(self.root if path == '/' else path, flags, *args, **kwargs)
        def stat_fake(fd):
            s = real_fstat(fd)
            # Keep ns fields for file-stability comparisons.
            return types.SimpleNamespace(st_mode=s.st_mode, st_uid=0, st_nlink=s.st_nlink,
                                         st_dev=s.st_dev, st_ino=s.st_ino, st_size=s.st_size,
                                         st_mtime_ns=s.st_mtime_ns, st_ctime_ns=s.st_ctime_ns)
        self.open_patch = mock.patch.object(r.os, 'open', open_fake)
        self.stat_patch = mock.patch.object(r.os, 'fstat', stat_fake)
        self.open_patch.start(); self.stat_patch.start()
        self.addCleanup(self.open_patch.stop); self.addCleanup(self.stat_patch.stop)
    def test_safe_file(self): self.assertEqual(r.read_owned('/sealed/file', private=True), b'sealed')
    def test_symlink_file_and_ancestor(self):
        (self.root / 'sealed/link').symlink_to('file')
        (self.root / 'alias').symlink_to('sealed')
        for path in ('/sealed/link', '/alias/file'):
            with self.subTest(path=path):
                with self.assertRaises((r.Refused, OSError)): r.read_owned(path)
    def test_hardlink_rejected(self):
        os.link(self.root / 'sealed/file', self.root / 'sealed/other')
        with self.assertRaises(r.Refused): r.read_owned('/sealed/file')
    def test_fifo_and_writable_file_or_ancestor_rejected(self):
        os.mkfifo(self.root / 'sealed/fifo', mode=0o600)
        with self.assertRaises(r.Refused): r.read_owned('/sealed/fifo')
        (self.root / 'sealed/file').chmod(0o666)
        with self.assertRaises(r.Refused): r.read_owned('/sealed/file')
        (self.root / 'sealed/file').chmod(0o600)
        (self.root / 'sealed').chmod(0o777)
        with self.assertRaises(r.Refused): r.read_owned('/sealed/file')
    def test_wrong_owner_oversize_or_changed_file_refused(self):
        previous = r.os.fstat
        def foreign(fd):
            value = previous(fd); value.st_uid = 99999; return value
        with mock.patch.object(r.os, 'fstat', foreign):
            with self.assertRaises(r.Refused): r.read_owned('/sealed/file')
        with self.assertRaises(r.Refused): r.read_owned('/sealed/file', limit=2)
        count = [0]
        def drift(fd):
            value = previous(fd); count[0] += 1
            if count[0] >= 3: value.st_ctime_ns += 1
            return value
        with mock.patch.object(r.os, 'fstat', drift):
            with self.assertRaises(r.Refused): r.read_owned('/sealed/file')

    def test_escape_and_noncanonical_paths(self):
        for path in ('/sealed/../file', 'sealed/file', '//sealed/file', '/sealed//file'):
            with self.subTest(path=path):
                with self.assertRaises(r.Refused): r.read_owned(path)


class CLITests(unittest.TestCase):
    def test_offline_cli_only_and_sanitized_refusal(self):
        ir, domains, rendered = fixture(); plan = r.derive_plan(ir, domains, rendered)
        sample = observations(plan)
        fixture_data = {'ir': ir, 'domains': domains, 'rendered': {n: b.decode() for n, b in rendered.items()},
                        'attemptStartMonotonicUSec': 1_000_000, 'samples': [sample] * 3}
        with tempfile.TemporaryDirectory(prefix='native-readiness-cli-') as temp:
            path = Path(temp) / 'fixture.json'; path.write_bytes(encoded(fixture_data))
            result = subprocess.run([sys.executable, '-B', str(SOURCE), '--offline-fixture', str(path)],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['proofClass'], 'synthetic-offline-only')
            sample['units']['rootful']['webservices-edge.service']['Result'] = 'PRIVATE_SENTINEL'
            path.write_bytes(encoded(fixture_data))
            result = subprocess.run([sys.executable, '-B', str(SOURCE), '--offline-fixture', str(path)],
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('PRIVATE_SENTINEL', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
