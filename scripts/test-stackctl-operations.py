#!/usr/bin/env python3
"""Isolated metadata/unit-state contracts; no real service or app operations."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parent / 'lib/stackctl-operations.py'
spec = importlib.util.spec_from_file_location('stackctl_operations_test', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
REAL_ACL_ENTRIES = m.acl_entries


class Operations(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='stackctl-operations-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'state'
        self.release = self.root / 'releases/selected-1'
        self.scope = self.base / 'scope'
        self.actor = self.scope / 'actor'
        self.actor_release = self.actor / 'releases/selected-1'
        self.user = 'webservices-lab-apps'
        self.uid = 780
        self.operator_uid = 1000
        self.operator_gid = 1000
        self.scope_gid = 1500  # exact stack group, distinct from operator primary
        self.subid = 200000
        self.binding = {'schemaVersion': 1, 'kind': 'standalone-stack-storage', 'site': 'synthetic',
            'scope': {'root': str(self.scope), 'dataClass': 'synthetic'},
            'domains': [{'name': 'apps', 'user': self.user, 'uid': self.uid,
                         'stateRoot': str(self.actor), 'graphRoot': str(self.scope / 'graph'),
                         'volumeRoot': str(self.scope / 'volumes')}],
            'roots': sorted(str(path) for path in (self.actor, self.scope / 'graph', self.scope / 'volumes'))}
        self.metadata = {'schemaVersion': 1, 'deploymentMode': 'standalone',
            'installerStateRoot': str(self.root), 'storageScope': self.binding['scope'],
            'domains': [dict(self.binding['domains'][0], services=['app', 'seed'])]}
        self.services = {'edge': {'placement': 'rootful', 'lifecycle': 'daemon'},
                         'app': {'placement': 'rootless', 'rootlessDomain': 'apps', 'lifecycle': 'daemon'},
                         'seed': {'placement': 'rootless', 'rootlessDomain': 'apps', 'lifecycle': 'oneshot'}}
        self.journal = m.journal_module()
        self.commands = []
        self.rows = {}
        self.owner_overrides = {}
        self.gid_overrides = {}
        self.command_failure = None
        self.command_hook = None
        self.write(self.root / '.install.lock', b'', 0o600)
        self.write(self.scope / '.stack-installation.json', self.binding, 0o600)
        self.actor_release.mkdir(parents=True)
        for directory in (self.actor, self.actor / 'releases', self.actor_release):
            directory.chmod(0o700)
        self.scope.chmod(0o2770)
        for name in ('actor', 'graph', 'volumes'):
            (self.scope / name).mkdir(exist_ok=True)
            (self.scope / name).chmod(0o700)
        (self.actor / 'current').symlink_to(self.actor_release)
        self.write(self.release / 'bundle.json', {'schemaVersion': 1})
        self.write(self.release / 'stack.ir.json', {'services': self.services})
        self.write(self.release / 'source-provenance.json', {})
        self.write(self.release / 'podman-domains.json', self.metadata)
        self.write(self.release / 'site/manifest.json', {'site': 'synthetic',
            'deploymentMode': 'standalone', 'installerStateRoot': str(self.root),
            'storageScope': self.binding['scope']})
        self.intent = {'schemaVersion': 1, 'phase': 'active', 'release': str(self.release),
                       'inputs': self.journal.fingerprint(self.release),
                       'steps': list(self.journal.PHASES[:5]), 'previousRelease': None}
        self.save_intent()
        self.root.chmod(0o700)
        self.release.chmod(0o700)
        (self.root / 'current').symlink_to(self.release)
        self.fixed_roots = ('/etc', '/usr/lib/systemd/user', '/run/systemd', '/run/user', '/home')
        self.install_sources('rootful', ['edge'])
        self.install_sources('rootless-apps', ['app', 'seed'])
        self.write(self.map_path('/usr/lib/systemd/user/podman.socket'), '[Socket]\nListenStream=%t/podman/podman.sock\n')
        self.write(self.map_path('/usr/lib/systemd/user/podman.service'), '[Service]\nExecStart=/usr/bin/podman system service\n')
        for name in ('webservices-auto-update.timer', 'webservices-auto-update.service'):
            data = '[Unit]\nDescription=synthetic auto update\n'
            self.write(self.release / 'ops' / name, data)
            self.write(self.map_path('/etc/systemd/system') / name, data)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(m, 'Path', side_effect=self.map_path))
        self.stack.enter_context(patch.object(m, 'info', side_effect=self.fake_info))
        self.stack.enter_context(patch.object(m.os, 'geteuid', return_value=0))
        self.real_open, self.real_fstat, self.real_fcntl = os.open, os.fstat, m.fcntl.fcntl
        self.fds = {}
        self.stack.enter_context(patch.object(m.os, 'open', side_effect=self.fake_open))
        self.stack.enter_context(patch.object(m.os, 'fstat', side_effect=self.fake_fstat))
        self.stack.enter_context(patch.object(m.fcntl, 'fcntl', side_effect=self.fake_fcntl))
        self.stack.enter_context(patch.object(m.pwd, 'getpwnam', side_effect=self.account))
        self.stack.enter_context(patch.object(m.pwd, 'getpwuid', side_effect=self.operator_account))
        self.stack.enter_context(patch.object(m.grp, 'getgrnam', side_effect=self.stack_group))
        self.stack.enter_context(patch.object(m, 'journal_module', return_value=self.journal))
        self.stack.enter_context(patch.object(self.journal, 'offline_subordinate_start', return_value=self.subid))
        self.offline = self.stack.enter_context(patch.object(self.journal, 'offline_actor', return_value=None))
        self.offline_verify = self.stack.enter_context(patch.object(self.journal, 'verify_offline_actor'))
        self.acl = self.stack.enter_context(patch.object(m, 'acl_entries', side_effect=self.storage_acl))
        self.marker_gate = self.stack.enter_context(patch.object(self.journal, 'standalone_binding', return_value=self.binding))
        self.journal_write = self.stack.enter_context(patch.object(self.journal, 'write', side_effect=self.write_journal))
        self.subprocess = self.stack.enter_context(patch.object(m.subprocess, 'run', side_effect=self.execute))
        # Journal helper's pin hashing reads ONLY this fixture, before mocking
        # subprocess. All subsequent execution must go through execute().
        self.plan = m.plans(self.root, self.release, self.metadata, self.binding)
        for plan in self.plan:
            self.rows[plan['role']] = {}
            for name, unit in plan['units'].items():
                generated = self.map_path('/run/systemd/generator') if plan['uid'] == 0 else self.map_path('/run/user') / str(self.uid) / 'systemd/generator'
                fragment = str(generated / name) if unit['generated'] else unit['sourcePath']
                if unit['generated']:
                    self.write(Path(fragment), '[Service]\nExecStart=/usr/bin/true\n')
                row = dict.fromkeys(m.PROPERTIES, '')
                row.update(Id=name, LoadState='loaded', ActiveState='active',
                    SubState='listening' if name.endswith('.socket') else 'running',
                    Type='oneshot' if unit['lifecycle'] in ('oneshot', 'producer', 'resource') else 'simple',
                    Result='success', ExecMainStatus='0', ExecMainCode='1',
                    ExecMainStartTimestampMonotonic='12345', Job='0', FragmentPath=fragment,
                    SourcePath=unit['sourcePath'] if unit['generated'] else '', UnitFileState='enabled',
                    RefuseManualStart='no')
                self.rows[plan['role']][name] = row

    def map_path(self, *args):
        path = Path(*args)
        if path.is_absolute():
            for root in self.fixed_roots:
                if path == Path(root) or path.is_relative_to(root):
                    return self.base / str(path).lstrip('/')
        return path

    def write(self, path, value, mode=0o644):
        self.assertTrue(path.is_relative_to(self.base), 'fixture write escaped temporary root')
        missing = []
        parent = path.parent
        while not parent.exists():
            missing.append(parent)
            parent = parent.parent
        for parent in reversed(missing):
            parent.mkdir(mode=0o700)
            parent.chmod(0o700)  # fixture only: clear inherited SGID/ambient umask
        if isinstance(value, dict):
            value = json.dumps(value, sort_keys=True).encode()
        if isinstance(value, str):
            value = value.encode()
        path.write_bytes(value)
        path.chmod(mode)

    def save_intent(self):
        self.write(self.root / '.install-intent.json', self.intent, 0o600)
        self.write(self.release / 'installation-receipt.json', self.intent, 0o600)

    def install_sources(self, role, names):
        self.fixed_roots = ('/etc', '/usr/lib/systemd/user', '/run/systemd', '/run/user', '/home')
        root = self.release / 'quadlet' / role
        if role == 'rootful':
            quadlets = self.map_path('/etc/containers/systemd')
            units = self.map_path('/etc/systemd/system')
        else:
            home = self.map_path('/home/' + self.user)
            quadlets, units = home / '.config/containers/systemd', home / '.config/systemd/user'
        files = {'webservices.target': '[Unit]\nWants=webservices-apps.target\n',
                 'webservices-apps.target': '[Unit]\nDescription=synthetic selected apps\n',
                 'webservices-internal.network': '[Network]\nNetworkName=synthetic\n'}
        for name in names:
            files['webservices-' + name + '.container'] = '[Container]\nImage=synthetic\n'
        if role != 'rootful':
            files['webservices-app.build'] = '[Build]\nImageTag=synthetic\n'
        for name, data in files.items():
            self.write(root / name, data)
            self.write((units if name.endswith('.target') else quadlets) / name, data)
        state_root = self.root if role == 'rootful' else self.actor
        runtime_dir = '/run/webservices' if role == 'rootful' else '/run/user/' + str(self.uid) + '/webservices'
        self.write(units / 'webservices-runtime-env.service', m.runtime_env_unit(state_root / 'runtime-env', runtime_dir))
        if role != 'rootful':
            self.write(quadlets.parent / 'storage.conf',
                f'[storage]\ndriver = "overlay"\ngraphroot = "{self.scope / "graph"}"\n', 0o600)
            self.write(quadlets.parent / 'containers.conf',
                '[network]\ndefault_rootless_network_cmd = "pasta"\npasta_options = ["--map-host-loopback", "169.254.1.2"]\n', 0o600)

    def owner(self, path):
        path = Path(path)
        if path in self.owner_overrides:
            return self.owner_overrides[path]
        if path == self.scope:
            return self.operator_uid
        if (any(path.is_relative_to(self.scope / name) for name in ('actor', 'graph', 'volumes'))
                or path.is_relative_to(self.base / 'home' / self.user)
                or path.is_relative_to(self.base / 'run/user' / str(self.uid))):
            return self.uid
        return 0

    def projected(self, value, path):
        owner = self.owner(path)
        gid = self.gid_overrides.get(path, self.scope_gid if path == self.scope else (self.uid if owner == self.uid else 0))
        return SimpleNamespace(st_mode=value.st_mode, st_uid=owner, st_gid=gid, st_nlink=value.st_nlink,
                               st_size=value.st_size, st_ino=value.st_ino, st_dev=value.st_dev,
                               st_mtime_ns=value.st_mtime_ns, st_ctime_ns=value.st_ctime_ns)

    def fake_info(self, path):
        return self.projected(path.lstat(), path)

    def fake_open(self, path, flags, *args, **kwargs):
        fd = self.real_open(path, flags, *args, **kwargs)
        self.fds[fd] = (self.fds[kwargs['dir_fd']] / path if 'dir_fd' in kwargs else Path(path))
        return fd

    def fake_fstat(self, fd):
        return self.projected(self.real_fstat(fd), self.fds[fd])

    def fake_fcntl(self, fd, operation, *args):
        result = self.real_fcntl(fd, operation, *args)
        if operation == m.fcntl.F_DUPFD_CLOEXEC:
            self.fds[result] = self.fds[fd]
        return result

    def account(self, name):
        self.assertEqual(name, self.user)
        return SimpleNamespace(pw_name=self.user, pw_uid=self.uid, pw_gid=self.uid, pw_dir='/home/' + self.user)

    def operator_account(self, uid):
        self.assertEqual(uid, self.operator_uid)
        return SimpleNamespace(pw_name='synthetic-operator', pw_uid=uid, pw_gid=self.operator_gid)

    def stack_group(self, name):
        self.assertEqual(name, 'stack')
        return SimpleNamespace(gr_name='stack', gr_gid=1500, gr_mem=['synthetic-operator'])

    def storage_acl(self, fd=None):
        if fd is not None:
            self.assertEqual(self.fds[fd], self.scope)
        return {('user', ''): 'rwx', ('group', ''): 'rwx', ('other', ''): '---',
                ('mask', ''): 'rwx', ('user', str(self.uid)): '--x',
                ('user', str(self.subid)): '--x'}

    def write_journal(self, path, value):
        self.assertIn(path, (self.root / '.install-intent.json', self.release / 'installation-receipt.json'))
        self.write(path, value, 0o600)

    def execute(self, command, **kwargs):
        self.assertEqual(kwargs['timeout'], 30)
        self.assertEqual(kwargs['cwd'], '/')
        self.assertEqual(kwargs['env']['LC_ALL'], 'C')
        self.assertNotIn('SYSTEMD_BUS_ADDRESS', kwargs['env'])
        self.commands.append(command)
        role = 'rootless-apps' if '--user' in command else 'rootful'
        rows = self.rows[role]
        if hasattr(self, 'updater_probe') and command[1:4] == ['show', *m.LEGACY_UPDATERS]:
            text = '\n\n'.join('\n'.join(k + '=' + v for k, v in row.items()) for row in self.updater_probe.values())
            return SimpleNamespace(returncode=0, stdout=text)
        if 'show' in command:
            names = [name for name in command[command.index('show') + 1: command.index('-p')] if name != '--all']
            text = '\n\n'.join('\n'.join(key + '=' + value for key, value in rows[name].items()) for name in names)
            return SimpleNamespace(returncode=0, stdout=text)
        if self.command_hook:
            self.command_hook(command)
        if self.command_failure and self.command_failure in command:
            return SimpleNamespace(returncode=1, stdout='')
        for action in ('start', 'stop', 'disable'):
            if action not in command:
                continue
            names = command[command.index(action) + 1:]
            for name in names:
                self.assertIn(name, rows)
                self.assertNotIn('*', name)
                if action == 'disable':
                    rows[name]['UnitFileState'] = 'disabled'
                elif action == 'stop':
                    rows[name].update(ActiveState='inactive', Job='0')
                else:
                    selected = rows if name == 'webservices.target' else {name: rows[name]}
                    for row in selected.values():
                        row.update(ActiveState='active', Job='0')
        return SimpleNamespace(returncode=0, stdout='')

    def verify(self):
        return m.operate('verify', self.root, journal=self.journal)

    def op(self, action, proof=None):
        return m.operate(action, self.root, proof or self.verify(), self.journal, wait_seconds=0)

    def mutations(self):
        return [command for command in self.commands if 'show' not in command]

    def test_verify_is_native_only_and_read_only(self):
        before = (self.root / '.install-intent.json').read_bytes()
        result = self.verify()
        self.assertTrue(result['nativeHealthy'])
        self.assertEqual(result['applicationAcceptance'], 'unproven')
        self.assertEqual(result['acceptedIntegratedInstalls'], 0)
        self.assertFalse(result['containerRuntimeDirectlyInvoked'])
        self.assertFalse(result['nativeServiceMutationsPerformed'])
        self.assertEqual(len(result['planSha256']), 64)
        self.assertEqual(before, (self.root / '.install-intent.json').read_bytes())
        self.assertEqual(self.mutations(), [])
        self.marker_gate.assert_called()
        self.journal_write.assert_not_called()

    def test_stop_exact_services_resources_targets_timers_api_only(self):
        result = self.op('stop')
        self.assertTrue(result['nativeStopped'])
        self.assertFalse(result['nativeHealthy'])
        for plan in self.plan:
            stops = [cmd for cmd in self.mutations() if 'stop' in cmd and ('--user' in cmd) == (plan['uid'] != 0)]
            self.assertEqual(len(stops), 1)
            self.assertEqual(set(stops[0][stops[0].index('stop') + 1:]), set(plan['units']))
        all_words = sum(self.mutations(), [])
        self.assertIn('webservices-auto-update.timer', all_words)
        self.assertIn('webservices-auto-update.service', all_words)
        self.assertIn('podman.socket', all_words)
        self.assertIn('podman.service', all_words)
        for word in ('user@19001.service', 'platform-zero-worklanes.service', 'p0-web.service', 'kill', 'reset-failed', 'daemon-reload', 'restart', 'podman'):
            self.assertNotIn(word, all_words)
        self.journal_write.assert_not_called()

    def test_start_after_stop_uses_new_exact_proof_without_enabling_updates(self):
        self.op('stop')
        self.commands.clear()
        result = self.op('start')
        self.assertTrue(result['nativeHealthy'])
        mutations = self.mutations()
        self.assertEqual(len(mutations), 3)
        self.assertEqual([cmd[cmd.index('start') + 1:] for cmd in mutations],
                         [['webservices.target'], ['podman.socket'], ['webservices.target']])
        self.assertNotIn('enable', sum(mutations, []))
        self.assertNotIn('webservices-auto-update.timer', sum(mutations, []))

    def test_all_cas_fields_are_mandatory_and_exact_before_mutation(self):
        proof = self.verify()
        for key in ('selectedRelease', 'intentSha256', 'receiptSha256', 'planSha256'):
            for replacement in (None, 'stale'):
                wrong = dict(proof)
                wrong[key] = replacement
                with self.assertRaises(ValueError):
                    self.op('start', wrong)
        self.assertEqual(self.mutations(), [])
        self.journal_write.assert_not_called()

    def test_failed_pending_and_retired_phases_cannot_start_even_with_exact_proof(self):
        for phase in ('preparing', 'units-selected', 'building', 'starting', 'failed', 'retired-failed'):
            self.intent['phase'] = phase
            self.save_intent()
            proof = self.verify()
            self.assertFalse(proof['nativeHealthy'])
            with self.assertRaises(ValueError):
                self.op('start', proof)
        self.assertEqual(self.mutations(), [])

    def test_active_receipt_with_failed_history_is_not_start_compatible(self):
        self.intent['steps'].insert(0, 'failed')
        self.save_intent()
        with self.assertRaises(ValueError):
            self.op('start')
        self.assertEqual(self.mutations(), [])

    def test_failed_selection_can_only_be_stopped_not_retired(self):
        self.intent['phase'] = 'failed'
        self.save_intent()
        result = self.op('stop')
        self.assertTrue(result['nativeStopped'])
        self.assertEqual(result['journalPhase'], 'failed')
        self.journal_write.assert_not_called()

    def test_command_failure_records_existing_failed_journal_and_no_replay(self):
        self.command_failure = 'start'
        with self.assertRaises(ValueError):
            self.op('start')
        self.assertEqual(m.load(self.root / '.install-intent.json', private=True)['phase'], 'failed')
        self.assertEqual(self.journal_write.call_count, 2)
        self.assertEqual(len([cmd for cmd in self.mutations() if 'stop' in cmd]), 2)
        self.assertEqual(len([cmd for cmd in self.mutations() if 'disable' in cmd]), 2)
        self.commands.clear()
        self.command_failure = None
        with self.assertRaises(ValueError):
            self.op('start')
        self.assertEqual(self.mutations(), [])

    def test_oneshot_never_executed_nonzero_failed_and_job_are_not_success(self):
        row = self.rows['rootless-apps']['webservices-seed.service']
        row['ActiveState'] = 'inactive'
        self.assertTrue(self.verify()['nativeHealthy'])
        good = dict(row)
        for changes in ({'ExecMainStartTimestampMonotonic': '0'}, {'ExecMainStatus': '1'},
                        {'ExecMainCode': '0'}, {'Result': 'exit-code'}, {'Job': '1'},
                        {'ActiveState': 'failed'}, {'Type': 'simple'}):
            row.update(changes)
            self.assertFalse(self.verify()['nativeHealthy'], changes)
            row.update(good)
        self.assertEqual(self.mutations(), [])

    def test_frozen_producer_is_intentionally_inert_not_a_completed_oneshot(self):
        self.services['app']['frozenBuildImage'] = 'sha256:' + 'a' * 64
        self.write(self.release / 'stack.ir.json', {'services': self.services})
        for path in (self.release / 'quadlet/rootless-apps/webservices-app.build',
                     self.map_path('/home/' + self.user + '/.config/containers/systemd/webservices-app.build')):
            self.write(path, b'[Unit]\nRefuseManualStart=yes\n\n' + path.read_bytes())
        self.intent['inputs'] = self.journal.fingerprint(self.release)
        self.save_intent()
        row = self.rows['rootless-apps']['webservices-app-build.service']
        row.update(ActiveState='inactive', ExecMainStartTimestampMonotonic='0', RefuseManualStart='yes')
        result = self.verify()
        self.assertTrue(result['nativeHealthy'])
        units = {unit['name']: unit for domain in result['domains'] for unit in domain['units']}
        self.assertEqual(units['webservices-app-build.service']['lifecycle'], 'inert-producer')
        row['RefuseManualStart'] = 'no'
        self.assertFalse(self.verify()['nativeHealthy'])
        self.assertEqual(self.mutations(), [])

    def test_daemon_exit_and_dead_api_socket_are_not_native_health(self):
        row = self.rows['rootless-apps']['webservices-app.service']
        row['SubState'] = 'exited'
        self.assertFalse(self.verify()['nativeHealthy'])
        row['SubState'] = 'running'
        row['Type'] = 'oneshot'
        self.assertFalse(self.verify()['nativeHealthy'])
        row['Type'] = 'simple'
        self.rows['rootless-apps']['podman.socket'].update(ActiveState='inactive', SubState='dead')
        self.assertFalse(self.verify()['nativeHealthy'])
        self.assertEqual(self.mutations(), [])

    def test_on_demand_inactive_is_not_application_acceptance(self):
        self.rows['rootless-apps']['podman.service']['ActiveState'] = 'inactive'
        result = self.verify()
        self.assertTrue(result['nativeHealthy'])
        self.assertEqual(result['applicationAcceptance'], 'unproven')

    def test_duplicate_missing_foreign_or_unloaded_states_refused(self):
        row = self.rows['rootful']['webservices-edge.service']
        for value in ('foreign.service', 'webservices.target'):
            row['Id'] = value
            with self.assertRaises(ValueError):
                self.verify()
        row['Id'] = 'webservices-edge.service'
        row['LoadState'] = 'not-found'
        with self.assertRaises(ValueError):
            self.verify()
        row['LoadState'] = 'loaded'
        del row['Type']
        with self.assertRaises(ValueError):
            self.verify()

    def test_source_fragment_dropins_and_propagation_escape_refused(self):
        row = self.rows['rootful']['webservices-edge.service']
        original = dict(row)
        for changes in ({'SourcePath': '/etc/foreign.container'}, {'FragmentPath': '/etc/foreign.service'},
                        {'DropInPaths': '/etc/foreign.conf'}, {'Requires': 'p0-web.service'},
                        {'Wants': 'platform-zero-worklanes.service'}, {'ConsistsOf': 'unrelated.service'},
                        {'BoundBy': 'unrelated.service'}, {'PropagatesStopTo': 'unrelated.service'}):
            row.update(changes)
            with self.assertRaises(ValueError):
                self.verify()
            row.update(original)
        self.assertEqual(self.mutations(), [])

    def test_installer_dropin_is_hashed_but_other_dropins_refused(self):
        row = self.rows['rootful']['webservices.target']
        path = self.map_path('/etc/systemd/system/webservices.target.d/10-runtime-env.conf')
        self.write(path, m.RUNTIME_DROPIN)
        first = self.verify()
        row['DropInPaths'] = str(path)
        second = self.verify()
        self.assertNotEqual(first['planSha256'], second['planSha256'])
        self.write(path, '[Unit]\nRequires=webservices-runtime-env.service\nAfter=foreign.service\n')
        with self.assertRaises(ValueError):
            self.verify()

    def test_input_receipt_marker_and_installed_bytes_are_all_bound(self):
        paths = [self.release / 'stack.ir.json', self.release / 'installation-receipt.json',
                 self.scope / '.stack-installation.json',
                 self.map_path('/etc/containers/systemd/webservices-edge.container')]
        for path in paths:
            original = path.read_bytes()
            self.write(path, '{}', 0o600 if path.name.endswith('receipt.json') else 0o644)
            with self.assertRaises(ValueError):
                self.verify()
            self.write(path, original, 0o600 if path.name.endswith('receipt.json') or path.name == '.stack-installation.json' else 0o644)
        self.assertEqual(self.mutations(), [])

    def test_missing_optional_pin_cannot_be_replaced_by_linked_parent(self):
        target = self.base / 'not-selected'
        target.mkdir()
        (self.release / 'site/global.settings').symlink_to(target, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)):
            self.verify()

    def test_pointer_escape_plain_pointer_and_rootless_selection_drift_refused(self):
        for path, owner in ((self.root / 'current', 0), (self.actor / 'current', self.uid)):
            original = os.readlink(path)
            path.unlink()
            path.symlink_to(self.base)
            with self.assertRaises(ValueError):
                self.verify()
            path.unlink()
            self.write(path, original)
            with self.assertRaises(ValueError):
                self.verify()
            path.unlink()
            path.symlink_to(original)
        self.assertTrue(self.verify()['nativeHealthy'])

    def test_symlink_hardlink_and_foreign_owner_files_fail_closed(self):
        path = self.map_path('/etc/containers/systemd/webservices-edge.container')
        original = path.read_bytes()
        other = self.base / 'other'
        self.write(other, original)
        path.unlink()
        path.symlink_to(other)
        with self.assertRaises((OSError, ValueError)):
            self.verify()
        path.unlink()
        os.link(other, path)
        with self.assertRaises(ValueError):
            self.verify()
        path.unlink()
        self.write(path, original)
        self.owner_overrides[path] = 55555
        with self.assertRaises(ValueError):
            self.verify()
        self.owner_overrides.clear()
        path.chmod(0o666)
        with self.assertRaises(ValueError):
            self.verify()
        self.assertEqual(self.mutations(), [])

    def test_unemitted_volume_unit_is_not_adopted_or_stopped(self):
        self.write(self.release / 'quadlet/rootful/webservices-authored.volume',
                   '[Volume]\nVolumeName=unrelated\nRemoveOnStop=yes\n')
        with self.assertRaises(ValueError):
            self.verify()
        self.assertEqual(self.mutations(), [])

    def test_directory_symlink_and_nonroot_are_refused(self):
        with patch.object(m.os, 'geteuid', return_value=1000):
            with self.assertRaises(ValueError):
                self.verify()
        path = self.release / 'quadlet/rootful'
        moved = self.release / 'quadlet/moved'
        path.rename(moved)
        path.symlink_to(moved, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)):
            self.verify()

    def test_relative_root_lock_hardlink_permissions_and_contention_refused(self):
        with self.assertRaises(ValueError):
            m.operate('verify', Path('relative'), journal=self.journal)
        lock = self.root / '.install.lock'
        lock.chmod(0o644)
        with self.assertRaises(ValueError):
            self.verify()
        lock.chmod(0o600)
        os.link(lock, self.base / 'lock-alias')
        with self.assertRaises(ValueError):
            self.verify()
        (self.base / 'lock-alias').unlink()
        fd = self.real_open(lock, os.O_RDWR)
        try:
            m.fcntl.flock(fd, m.fcntl.LOCK_EX | m.fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.verify()
        finally:
            os.close(fd)
        self.assertEqual(self.mutations(), [])

    def test_cas_is_rechecked_before_second_role_and_after_mutation(self):
        proof = self.verify()
        def change(command):
            if 'start' in command:
                self.intent['previousRelease'] = 'changed-after-dispatch'
                self.save_intent()
        self.command_hook = change
        with self.assertRaises(ValueError):
            self.op('start', proof)
        self.assertEqual(len(self.mutations()), 1)
        # Never overwrite concurrent installer authority to record our failure.
        self.journal_write.assert_not_called()

    def test_changed_generated_fragment_invalidates_plan_cas(self):
        proof = self.verify()
        path = Path(self.rows['rootful']['webservices-edge.service']['FragmentPath'])
        self.write(path, '[Service]\nExecStart=/usr/bin/false\n')
        with self.assertRaises(ValueError):
            self.op('start', proof)
        self.assertEqual(self.mutations(), [])

    def test_managed_venue_and_stale_marker_gate_are_not_adopted(self):
        for changes in ({'deploymentMode': 'managed'}, {'venue': {}}, {'installerStateRoot': '/different'}):
            data = dict(self.metadata, **changes)
            self.write(self.release / 'podman-domains.json', data)
            self.intent['inputs'] = self.journal.fingerprint(self.release)
            self.save_intent()
            with self.assertRaises(ValueError):
                self.verify()
        self.write(self.release / 'podman-domains.json', self.metadata)
        self.intent['inputs'] = self.journal.fingerprint(self.release)
        self.save_intent()
        self.marker_gate.side_effect = ValueError('ownership/ACL failure')
        with self.assertRaises(ValueError):
            self.verify()
        self.assertEqual(self.mutations(), [])

    def test_native_failure_after_start_is_failed_journal_not_accepted(self):
        def unhealthy(command):
            if 'start' in command and '--user' in command:
                self.rows['rootless-apps']['webservices-app.service']['Result'] = 'exit-code'
        self.command_hook = unhealthy
        with self.assertRaises(ValueError):
            self.op('start')
        self.assertEqual(m.load(self.root / '.install-intent.json', private=True)['phase'], 'failed')

    def test_unit_type_specific_properties_are_not_fabricated(self):
        for rows in self.rows.values():
            for name, row in rows.items():
                if name.endswith('.target'):
                    for prop in m.SERVICE_PROPERTIES:
                        del row[prop]
                elif name.endswith(('.socket', '.timer')):
                    for prop in set(m.SERVICE_PROPERTIES) - {'Result'}:
                        del row[prop]
        self.assertTrue(self.verify()['nativeHealthy'])
        del self.rows['rootful']['webservices-auto-update.timer']['Result']
        with self.assertRaises(ValueError):
            self.verify()

    def test_stop_disable_failure_still_stops_all_owned_roles_and_records_failure(self):
        self.command_failure = 'disable'
        with self.assertRaises(ValueError):
            self.op('stop')
        self.assertEqual(len([cmd for cmd in self.mutations() if 'stop' in cmd]), 2)
        self.assertEqual(m.load(self.root / '.install-intent.json', private=True)['phase'], 'failed')
        self.assertTrue(all(row['ActiveState'] == 'inactive' for rows in self.rows.values() for row in rows.values()))

    def test_stop_never_claims_success_if_an_owned_unit_or_job_remains(self):
        original = self.execute
        def stuck(command, **kwargs):
            result = original(command, **kwargs)
            if 'stop' in command:
                self.rows['rootful']['webservices-edge.service'].update(ActiveState='active', Job='123')
            return result
        self.subprocess.side_effect = stuck
        with self.assertRaises(ValueError):
            self.op('stop')
        self.assertEqual(m.load(self.root / '.install-intent.json', private=True)['phase'], 'failed')

    def test_start_polls_wanted_services_instead_of_assuming_target_means_ready(self):
        original = self.execute
        self.pending = False
        def pending(command, **kwargs):
            result = original(command, **kwargs)
            if 'start' in command:
                self.pending = True
                self.rows['rootless-apps']['webservices-app.service'].update(ActiveState='activating', Job='123')
            return result
        def advance(seconds):
            self.rows['rootless-apps']['webservices-app.service'].update(ActiveState='active', Job='0')
        proof = self.verify()
        self.subprocess.side_effect = pending
        with patch.object(m.time, 'sleep', side_effect=advance) as sleep:
            result = m.operate('start', self.root, proof, self.journal, wait_seconds=1)
        self.assertTrue(self.pending)
        self.assertTrue(result['nativeHealthy'])
        sleep.assert_called()

    def test_marker_exact_bytes_and_lock_inode_are_in_plan_cas(self):
        proof = self.verify()
        marker = self.scope / '.stack-installation.json'
        self.write(marker, marker.read_bytes() + b'\n', 0o600)
        with self.assertRaises(ValueError):
            self.op('start', proof)
        proof = self.verify()
        lock = self.root / '.install.lock'
        replacement = self.root / '.new-lock'
        self.write(replacement, b'', 0o600)
        replacement.replace(lock)
        with self.assertRaises(ValueError):
            self.op('stop', proof)
        self.assertEqual(self.mutations(), [])

    def test_duplicate_json_and_legacy_unexpanded_receipts_are_refused(self):
        marker = self.scope / '.stack-installation.json'
        original = marker.read_bytes()
        self.write(marker, b'{"schemaVersion":1,"schemaVersion":1}', 0o600)
        with self.assertRaises(ValueError):
            self.verify()
        self.write(marker, original, 0o600)
        self.intent['inputs'] = {key: self.intent['inputs'][key] for key in self.journal.CORE_INPUTS}
        self.save_intent()
        with self.assertRaises(ValueError):
            self.verify()
        self.assertEqual(self.mutations(), [])

    def test_account_identity_uid_and_home_drift_refuse_without_dispatch(self):
        for account in (SimpleNamespace(pw_name=self.user, pw_uid=self.uid + 1, pw_gid=self.uid, pw_dir='/home/' + self.user),
                        SimpleNamespace(pw_name=self.user, pw_uid=self.uid, pw_gid=self.uid, pw_dir='/home/foreign')):
            with patch.object(m.pwd, 'getpwnam', return_value=account):
                with self.assertRaises(ValueError):
                    self.verify()
        self.assertEqual(self.mutations(), [])

    def test_runtime_unit_matches_installer_template_and_rejects_edits(self):
        # Source-only guard against template drift; never execute the installer.
        installer = (m.ROOT / 'runtime-generator/podman-ops/install-podman-bundle.sh').read_text()
        self.assertIn('Description=Restore rendered webservices environment files', installer)
        self.assertIn('RemainAfterExit=yes', installer)
        self.assertIn('Requires=webservices-runtime-env.service', installer)
        self.assertIn('After=webservices-runtime-env.service', installer)
        data = m.runtime_env_unit('/selected/runtime-env', '/run/webservices').decode()
        self.assertIn('for env_file in /selected/runtime-env/*.env;', data)
        self.assertIn('/usr/bin/install -m 0600 "$env_file" /run/webservices/; done\'', data)
        path = self.map_path('/home/' + self.user + '/.config/systemd/user/webservices-runtime-env.service')
        self.write(path, '[Service]\nExecStart=/usr/bin/false\n')
        with self.assertRaises(ValueError):
            self.verify()

    def test_query_failure_and_nonsecret_error_surface_are_fail_closed(self):
        self.subprocess.return_value = SimpleNamespace(returncode=1, stdout='')
        self.subprocess.side_effect = None
        with self.assertRaises(ValueError):
            self.verify()
        self.journal_write.assert_not_called()
        with patch.object(m, 'journal_module', return_value=self.journal), \
             contextlib.redirect_stderr(__import__('io').StringIO()) as error:
            self.assertEqual(m.main(['verify', '--state-root', str(self.root)]), 1)
        self.assertNotIn(str(self.root), error.getvalue())
        self.assertIn('operation refused', error.getvalue())

    def test_dirfd_read_cannot_follow_an_ancestor_swap(self):
        parent, moved, outside = self.base / 'race', self.base / 'race-old', self.base / 'outside'
        self.write(parent / 'leaf', b'original')
        self.write(outside / 'leaf', b'unselected')
        original = self.fake_open
        def replace_parent(path, flags, *args, **kwargs):
            if path == 'leaf' and 'dir_fd' in kwargs and not moved.exists():
                parent.rename(moved)
                parent.symlink_to(outside, target_is_directory=True)
            return original(path, flags, *args, **kwargs)
        with patch.object(m.os, 'open', side_effect=replace_parent):
            self.assertEqual(m.body(parent / 'leaf'), b'original')
        with self.assertRaises((OSError, ValueError)):
            m.body(parent / 'leaf')
        self.assertEqual(self.mutations(), [])

    def test_native_wait_is_bounded_and_not_an_arbitrary_execution_flag(self):
        for wait in (-1, 121, True, '120'):
            with self.assertRaises(ValueError):
                m.operate('start', self.root, {}, self.journal, wait_seconds=wait)
        with self.assertRaises(ValueError):
            m.operate('restart', self.root, {}, self.journal)
        self.assertEqual(self.mutations(), [])

    def set_offline(self, phase='retired-failed'):
        self.intent['phase'] = phase
        self.save_intent()
        actor = dict(self.binding['domains'][0])
        self.offline.side_effect = lambda release, role: actor if role == 'rootless-apps' else None
        return actor

    def test_real_model_operator_group_scope_actor_config_and_root_pointer(self):
        # No actual chown/ACL changes: projected identity over isolated inodes.
        self.assertEqual(stat.S_IMODE(self.scope.stat().st_mode), 0o2770)
        self.owner_overrides[self.actor / 'current'] = 0  # installer creates this as root
        self.assertTrue(self.verify()['nativeHealthy'])
        # Installed public trust and root/mapped data are not authority inputs.
        for name, owner in (('public-trust.pem', 0), ('mapped-data', self.subid + 27)):
            path = self.scope / 'volumes' / name
            self.write(path, 'synthetic app data')
            self.owner_overrides[path] = owner
        (self.scope / 'volumes/opaque-app-link').symlink_to('/unread/unselected')
        self.assertTrue(self.verify()['nativeHealthy'])
        self.assertEqual(self.mutations(), [])

    def test_seven_disjoint_lab_actors_share_only_exact_scope_execute_acl(self):
        binding = json.loads(json.dumps(self.binding))
        accounts = {self.user: self.account(self.user)}
        rows = binding['domains']
        for index in range(1, 7):
            uid, user = 780 + index, 'webservices-lab-' + str(index)
            account = SimpleNamespace(pw_name=user, pw_uid=uid, pw_gid=uid, pw_dir='/home/' + user)
            accounts[user] = account
            row = {'name': 'actor-' + str(index), 'user': user, 'uid': uid}
            for key in ('stateRoot', 'graphRoot', 'volumeRoot'):
                path = self.scope / (row['name'] + '-' + key)
                path.mkdir(mode=0o700)
                path.chmod(0o700)  # clear inherited setgid as the installer does
                self.owner_overrides[path] = uid
                row[key] = str(path)
            rows.append(row)
        binding['roots'] = sorted(row[key] for row in rows for key in ('stateRoot', 'graphRoot', 'volumeRoot'))
        acl = self.storage_acl()
        for index in range(1, 7):
            acl[('user', str(780 + index))] = '--x'
            acl[('user', str(self.subid + 65536 * index))] = '--x'
        self.acl.side_effect = None
        self.acl.return_value = acl
        original = self.projected
        def projected(value, path):
            result = original(value, path)
            if path in self.owner_overrides:
                result.st_gid = self.owner_overrides[path]
            return result
        starts = {user: self.subid + 65536 * index for index, user in enumerate(accounts)}
        with patch.object(m.pwd, 'getpwnam', side_effect=accounts.__getitem__), \
             patch.object(self.journal, 'offline_subordinate_start', side_effect=starts.__getitem__), \
             patch.object(self, 'projected', side_effect=projected):
            authority = m.StorageAuthority(binding)
            self.assertEqual(len(authority.private), 21)
            victim = Path(rows[1]['volumeRoot'])
            self.owner_overrides[victim] = rows[2]['uid']
            with self.assertRaises(ValueError):
                m.StorageAuthority(binding)
        self.assertEqual(self.commands, [])

    def test_private_roots_overlap_escape_symlink_and_subrange_refused(self):
        original = json.loads(json.dumps(self.binding))
        for path in (self.actor / 'nested', self.base / 'outside'):
            binding = json.loads(json.dumps(original))
            binding['domains'][0]['graphRoot'] = str(path)
            binding['roots'] = [row for row in original['roots'] if row != str(self.scope / 'graph')] + [str(path)]
            with self.assertRaises(ValueError):
                m.StorageAuthority(binding)
        graph = self.scope / 'graph'
        graph.rmdir()
        graph.symlink_to(self.actor, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)):
            self.verify()
        graph.unlink()
        graph.mkdir(mode=0o700)
        graph.chmod(0o700)
        with patch.object(self.journal, 'offline_subordinate_start', side_effect=ValueError('overlap')):
            with self.assertRaises(ValueError):
                self.verify()
        self.assertEqual(self.mutations(), [])

    def test_private_root_actor_mode_and_cross_domain_takeover_refused(self):
        for path in (self.actor, self.scope / 'graph', self.scope / 'volumes'):
            for owner in (0, self.uid + 1, self.subid):
                self.owner_overrides[path] = owner
                with self.assertRaises(ValueError):
                    self.verify()
            self.owner_overrides.pop(path)
            path.chmod(0o770)
            with self.assertRaises(ValueError):
                self.verify()
            path.chmod(0o700)
        self.assertEqual(self.mutations(), [])

    def test_scope_exception_does_not_relax_unknown_ancestors(self):
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):
            self.verify()
        self.root.chmod(0o700)
        self.base.chmod(0o770)
        with self.assertRaises(ValueError):
            self.verify()
        self.base.chmod(0o700)
        self.scope.chmod(0o2777)
        with self.assertRaises(ValueError):
            self.verify()
        self.scope.chmod(0o2770)
        self.scope_gid = 1501  # not root, operator primary, or exact stack group
        with self.assertRaises(ValueError):
            self.verify()
        self.assertEqual(self.mutations(), [])

    def test_storage_acl_cross_domain_broadening_missing_actor_and_mask_refused(self):
        good = self.storage_acl()
        for changes, removed in (({('user', '999'): '--x'}, None),
                                 ({('group', '999'): '--x'}, None),
                                 ({('user', str(self.uid)): 'r-x'}, None),
                                 ({('user', str(self.subid)): 'rwx'}, None),
                                 ({('mask', ''): 'rw-'}, None),
                                 ({('mask', ''): '--x'}, None),
                                 ({('other', ''): '--x'}, None),
                                 ({}, ('user', str(self.uid)))):
            acl = good | changes
            if removed:
                acl.pop(removed)
            self.acl.side_effect = None
            self.acl.return_value = acl
            with self.assertRaises(ValueError):
                self.verify()
        self.assertEqual(self.mutations(), [])

    def test_scope_acl_and_ownership_are_in_exact_plan_cas(self):
        proof = self.verify()
        self.scope.chmod(0o770)  # still valid, but not the verified identity
        with self.assertRaises(ValueError):
            self.op('stop', proof)
        self.scope.chmod(0o2770)
        good = self.storage_acl()
        good.pop(('user', str(self.subid)))  # permitted optional graph traversal, but CAS differs
        self.acl.side_effect = None
        self.acl.return_value = good
        with self.assertRaises(ValueError):
            self.op('stop', proof)
        self.assertEqual(self.mutations(), [])

    def test_actor_config_hash_owner_links_and_source_drift_refused(self):
        path = self.map_path('/home/' + self.user + '/.config/containers/storage.conf')
        original = path.read_bytes()
        self.write(path, original + b'#changed\n', 0o600)
        with self.assertRaises(ValueError):
            self.verify()
        self.write(path, original, 0o600)
        self.owner_overrides[path] = 0
        with self.assertRaises(ValueError):
            self.verify()
        self.owner_overrides.clear()
        other = path.with_name('unselected.conf')
        self.write(other, original, 0o600)
        path.unlink()
        path.symlink_to(other)
        with self.assertRaises((OSError, ValueError)):
            self.verify()
        path.unlink()
        os.link(other, path)
        with self.assertRaises(ValueError):
            self.verify()
        self.assertEqual(self.mutations(), [])

    def test_marker_mode_and_owner_fail_closed_under_supported_writable_scope(self):
        marker = self.scope / '.stack-installation.json'
        marker.chmod(0o644)
        with self.assertRaises(ValueError):
            self.verify()
        marker.chmod(0o600)
        self.owner_overrides[marker] = self.operator_uid
        with self.assertRaises(ValueError):
            self.verify()
        self.assertEqual(self.mutations(), [])

    def test_offline_verify_and_stop_reuse_canonical_proof_without_user_calls(self):
        actor = self.set_offline()
        verified = self.verify()
        self.assertFalse(verified['nativeHealthy'])
        domain = next(row for row in verified['domains'] if row['role'] == 'rootless-apps')
        self.assertTrue(domain['offlineManagerStopped'])
        self.assertTrue(all(row['activeState'] == 'unobserved' and not row['nativeHealthy']
                            for row in domain['units']))
        result = self.op('stop', verified)
        self.assertTrue(result['nativeStopped'])
        self.assertEqual(result['journalPhase'], 'retired-failed')
        self.assertFalse(any('--user' in cmd for cmd in self.commands))
        self.offline_verify.assert_called_with(actor, next(p['command'] for p in self.plan if p['uid']))
        self.journal_write.assert_not_called()
        self.assertTrue(self.verify()['nativeStopped'])

    def test_offline_failed_actor_never_started_even_with_exact_active_history(self):
        for phase in ('failed', 'retired-failed', 'active'):
            self.set_offline(phase)
            proof = self.verify()
            with self.assertRaises(ValueError):
                self.op('start', proof)
        self.assertEqual(self.mutations(), [])
        self.assertFalse(any('--user' in cmd for cmd in self.commands))
        self.journal_write.assert_not_called()

    def omit_native_updaters(self):
        self.fixed_roots += ('/usr/local',)
        directory = self.map_path('/usr/local/sbin')
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)
        directory.parent.chmod(0o700)
        self.updater_probe = {}
        for name in m.LEGACY_UPDATERS:
            path = self.map_path('/etc/systemd/system') / name
            if path.exists():
                path.unlink()  # only this isolated synthetic legacy fixture
            self.rows['rootful'].pop(name, None)
            row = dict.fromkeys(m.ABSENT_PROPERTIES, '')
            row.update(Id=name, LoadState='not-found', ActiveState='inactive', SubState='dead')
            self.updater_probe[name] = row

    def canonical_lifecycle(self):
        """Model commands/APIs only; no real NSS, /proc, managers or secrets."""
        self.commands.clear()
        self.omit_native_updaters()
        self.fixed_roots += ('/proc', '/usr/lib/systemd/system')
        self.boot = '12345678-1234-1234-1234-123456789abc'
        self.write(self.map_path('/proc/sys/kernel/random/boot_id'), self.boot + '\n')
        self.write(self.map_path('/usr/lib/systemd/system/user@.service'), '[Service]\nExecStart=/usr/lib/systemd/systemd --user\n')
        self.events = []
        self.manager = dict.fromkeys(m.MANAGER_PROPERTIES, '')
        self.manager.update(Id='user@780.service', LoadState='loaded', ActiveState='inactive', SubState='dead',
                            MainPID='0', Result='success', FragmentPath='/usr/lib/systemd/system/user@.service')
        self.sessions = []
        self.enabled_boot_units = ''
        self.boot_rows = {}
        for name in m.BOOT_UNITS:
            row = dict.fromkeys(m.BOOT_PROPERTIES, '')
            row.update(Id=name, LoadState='loaded', FragmentPath='/usr/lib/systemd/user/' + name)
            self.boot_rows[name] = row
            self.write(self.map_path(row['FragmentPath']), '[Unit]\nDescription=synthetic manager builtin\n')
        self.intent['nativeRuntimeEnvUnitCustody'] = {'roles': {
            p['role']: {'role': p['role'], 'release': str(self.release)} for p in self.plan}}
        self.intent['nativeRuntimeEnvUnits'] = {'kind': 'native-runtime-env-units', 'status': 'completed'}
        self.save_intent()
        template = lambda manifest: ('[Service]\nType=oneshot\n# exact synthetic role=' + manifest['role'] + '\n').encode()
        self.copy_cues = {p['role']: None for p in self.plan}
        self.source_sha = 'a' * 64
        canonical_sha = lambda value: m.sha((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode())
        def prepared(root, release, intent):
            self.events.append('prepared')
            self.assertEqual(self.fake_fstat(9).st_ino, self.root.joinpath('.install.lock').stat().st_ino)
            independent = self.real_open(self.root / '.install.lock', os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError):
                    m.fcntl.flock(independent, m.fcntl.LOCK_EX | m.fcntl.LOCK_NB)
            finally:
                os.close(independent)
            digest = m.sha(root.joinpath('.install-intent.json').read_bytes())
            return dict(schemaVersion=1, kind='native-prepared-runtime-env-unit-observation', status='completed',
                release=str(release), inputs=intent['inputs'], intentSha256=digest, receiptSha256=digest,
                sourceSha256=self.source_sha, copyCustodySha256=canonical_sha(self.copy_cues),
                bindingSha256=canonical_sha(dict(source=self.source_sha, cues=self.copy_cues)),
                runningEnvironmentChecked=False, journalWritten=False, activationAuthorized=False,
                readinessAuthorized=False, resetAuthorized=False)
        def seal(root, release, intent):
            self.events.append('root-seal')
            self.assertEqual(len([c for c in self.mutations() if c[-2:] == ['start', 'webservices-runtime-env.service']]), 2)
            digest = m.sha(self.root.joinpath('.install-intent.json').read_bytes())
            self.copy_cues = {p['role']: {'uid': 0, 'sha256': 'b' * 64, 'modelReceipt': p['role']} for p in self.plan}
            return dict(schemaVersion=1, kind='root-runtime-copy-observation', status='completed',
                        release=str(release), inputs=intent['inputs'], intentSha256=digest, receiptSha256=digest,
                        bootId=self.boot, copies={role: {'receipt': cue} for role, cue in self.copy_cues.items()},
                        activationAuthorized=False, readinessAuthorized=False, resetAuthorized=False, journalWritten=False)
        self.runtime = SimpleNamespace(render_unit=template, render_dropin=lambda: m.RUNTIME_DROPIN,
                                       verify_prepared_units=prepared, seal_running_copies=seal)
        self.runtime_loader = self.stack.enter_context(patch.object(m, 'runtime_api', return_value=self.runtime))
        for plan in self.plan:
            folder = Path(plan['units']['webservices-runtime-env.service']['sourcePath']).parent
            self.write(folder / 'webservices-runtime-env.service', template({'role': plan['role']}))
            self.write(folder / 'webservices.target.d/10-runtime-env.conf', m.RUNTIME_DROPIN)
            self.rows[plan['role']]['webservices.target']['DropInPaths'] = str(folder / 'webservices.target.d/10-runtime-env.conf')
        for name, row in self.rows['rootless-apps'].items():
            row.update(ActiveState='inactive', Job='0')
            if name in ('webservices.target', 'podman.socket'):
                row['UnitFileState'] = 'disabled'
        actor = dict(self.binding['domains'][0])
        self.offline.side_effect = lambda release, role: (actor if role == 'rootless-apps'
            and self.manager['ActiveState'] != 'active' else None)
        self.manager_outcome = 'running'
        self.lifecycle_hook = None
        original = self.execute
        def execute(command, **kwargs):
            if command[:3] == ['/usr/bin/systemctl', 'show', 'user@780.service']:
                self.commands.append(command)
                return SimpleNamespace(returncode=0, stdout='\n'.join(k + '=' + v for k, v in self.manager.items()))
            if command[:2] == ['/usr/bin/loginctl', 'list-sessions']:
                self.commands.append(command)
                return SimpleNamespace(returncode=0, stdout=json.dumps(self.sessions))
            if 'list-unit-files' in command:
                self.commands.append(command)
                self.assertIn('SYSTEMD_OFFLINE=1', command)
                self.assertIn('--no-reload', command)
                return SimpleNamespace(returncode=0, stdout=self.enabled_boot_units)
            if 'show' in command and 'default.target' in command:
                self.commands.append(command)
                text = '\n\n'.join('\n'.join(k + '=' + v for k, v in row.items()) for row in self.boot_rows.values())
                return SimpleNamespace(returncode=0, stdout=text)
            self.events.append(command[-1])
            if self.lifecycle_hook:
                self.lifecycle_hook(command)
            if command == ['/usr/bin/systemctl', 'start', 'user@780.service']:
                self.commands.append(command)
                if self.manager_outcome == 'running':
                    self.manager.update(ActiveState='active', SubState='running', MainPID='4321',
                        ControlGroup='/user.slice/user-780.slice/user@780.service')
                elif self.manager_outcome == 'pending':
                    self.manager.update(ActiveState='activating', SubState='start', Job='123')
                else:
                    self.manager.update(ActiveState='failed', SubState='failed', Result='exit-code')
                return SimpleNamespace(returncode=0, stdout='')
            return original(command, **kwargs)
        self.subprocess.side_effect = execute
        return self.verify()

    def start_commands(self):
        return [c for c in self.commands if 'start' in c]

    def test_canonical_stop_offline_start_restores_all_before_targets_and_root_seals(self):
        self.op('stop')
        proof = self.canonical_lifecycle()
        self.assertTrue(proof['nativeStopped'])
        before = self.root.joinpath('.install-intent.json').read_bytes()
        result = self.op('start', proof)
        self.assertTrue(result['nativeHealthy'])
        self.assertFalse(result['nativeStopped'])
        self.assertFalse(next(d for d in result['domains'] if d['role'] == 'rootless-apps')['offlineManagerStopped'])
        self.assertEqual(self.root.joinpath('.install-intent.json').read_bytes(), before)
        self.assertEqual([c[-1] for c in self.start_commands()], ['user@780.service',
            'webservices-runtime-env.service', 'webservices-runtime-env.service',
            'webservices.target', 'podman.socket', 'webservices.target'])
        self.assertLess(self.events.index('root-seal'), self.events.index('webservices.target'))
        self.assertLess(self.events.index('root-seal'), self.events.index('podman.socket'))
        self.assertNotEqual(result['planSha256'], proof['planSha256'])
        self.assertEqual(result['planSha256'], self.verify()['planSha256'])
        self.assertEqual(result['applicationAcceptance'], 'unproven')
        self.journal_write.assert_not_called()

    def install_login_barrier_fixture(self):
        path = self.map_path(m.LOGIN_BARRIER_PATH)
        self.write(path, m.LOGIN_BARRIER_BODY)
        self.assertEqual(m.sha(path.read_bytes()), '1c1452839b609b0609cccaba3c648d780372df6f244deb487da6da5ee002a993')
        self.manager['DropInPaths'] = m.LOGIN_BARRIER_PATH
        return path

    def test_reviewed_login_barrier_profile_positive_cold_restart_and_no_dropin_compatibility(self):
        self.op('stop')
        self.canonical_lifecycle()
        self.install_login_barrier_fixture()
        profile = m.manager_state(self.uid)['sourceProfile']
        self.assertEqual(profile['profile'], 'systemd-user-login-barrier-v1')
        self.assertEqual(profile['dropins'][0]['sha256'], m.LOGIN_BARRIER_SHA256)
        self.assertTrue(profile['dropins'][0]['pins'])
        result = self.op('start')
        self.assertTrue(result['nativeHealthy'])
        self.assertIn('root-seal', self.events)
        self.manager['DropInPaths'] = ''
        self.assertEqual(m.manager_state(self.uid)['sourceProfile']['profile'], 'systemd-user-no-dropins-v1')

    def test_login_barrier_rejects_body_owner_group_mode_and_ancestry_drift(self):
        self.canonical_lifecycle()
        path = self.install_login_barrier_fixture()
        for drift in ('body', 'owner', 'gid', 'mode', 'parent-owner', 'parent-writable'):
            with self.subTest(drift=drift):
                if drift == 'body':
                    self.write(path, m.LOGIN_BARRIER_BODY + b'# unreviewed edit\n')
                elif drift == 'owner':
                    self.owner_overrides[path] = self.uid
                elif drift == 'gid':
                    self.gid_overrides[path] = self.uid
                elif drift == 'mode':
                    path.chmod(0o640)
                elif drift == 'parent-owner':
                    self.owner_overrides[path.parent] = self.uid
                else:
                    path.parent.chmod(0o770)
                with self.assertRaises(ValueError):
                    m.manager_state(self.uid)
                self.owner_overrides.clear()
                self.gid_overrides.clear()
                self.write(path, m.LOGIN_BARRIER_BODY)
                path.parent.chmod(0o700)

    def test_login_barrier_unknown_local_runtime_additional_or_duplicate_paths_are_not_read(self):
        self.canonical_lifecycle()
        self.install_login_barrier_fixture()
        for paths in ('/etc/systemd/system/user@.service.d/10-login-barrier.conf',
                      '/run/systemd/system/user@.service.d/10-login-barrier.conf',
                      '/usr/lib/systemd/system/user@.service.d/99-other.conf',
                      m.LOGIN_BARRIER_PATH + ' ' + m.LOGIN_BARRIER_PATH,
                      m.LOGIN_BARRIER_PATH + ' /etc/foreign.conf'):
            self.manager['DropInPaths'] = paths
            with patch.object(m, 'manager_source') as read_source:
                with self.assertRaisesRegex(ValueError, 'Unowned selected manager'):
                    m.manager_state(self.uid)
                read_source.assert_not_called()

    def test_login_barrier_file_or_parent_links_and_access_default_acl_are_refused(self):
        self.canonical_lifecycle()
        path = self.install_login_barrier_fixture()
        other = self.base / 'other-public-vendor.conf'
        self.write(other, m.LOGIN_BARRIER_BODY)
        path.unlink(); path.symlink_to(other)
        with self.assertRaises(OSError):
            m.manager_state(self.uid)
        path.unlink(); os.link(other, path)
        with self.assertRaises(ValueError):
            m.manager_state(self.uid)
        path.unlink(); self.write(path, m.LOGIN_BARRIER_BODY)
        old = path.parent.with_name('old-vendor-directory')
        path.parent.rename(old)
        path.parent.symlink_to(old, target_is_directory=True)
        with self.assertRaises(OSError):
            m.manager_state(self.uid)
        path.parent.unlink(); old.rename(path.parent)
        original = m.os.getxattr
        for target, name in ((path, 'system.posix_acl_access'), (path.parent, 'system.posix_acl_default')):
            def acl(fd, attribute):
                return b'present-ACL' if self.fds[fd] == target and attribute == name else original(fd, attribute)
            with patch.object(m.os, 'getxattr', side_effect=acl):
                with self.assertRaisesRegex(ValueError, 'ACL present'):
                    m.manager_state(self.uid)

    def test_login_barrier_body_or_parent_aba_changes_manager_source_profile_and_stops_bootstrap(self):
        for moment in ('before-manager', 'after-manager'):
            self.canonical_lifecycle()
            path = self.install_login_barrier_fixture()
            before = m.manager_state(self.uid)['sourceProfile']
            changed = False
            def race(command):
                nonlocal changed
                trigger = 'user@780.service' if moment == 'before-manager' else 'webservices-runtime-env.service'
                if not changed and command[-1] == trigger:
                    changed = True
                    old = path.stat()
                    self.write(path, b'# transient unreviewed body\n')
                    self.write(path, m.LOGIN_BARRIER_BODY)
                    os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns + 1))
                    path.parent.chmod(0o750); path.parent.chmod(0o700)
            self.lifecycle_hook = race
            with self.assertRaises(ValueError):
                self.op('start')
            after = m.manager_state(self.uid)['sourceProfile']
            self.assertEqual(before['dropins'][0]['sha256'], after['dropins'][0]['sha256'])
            self.assertNotEqual(before, after)
            self.assertNotIn('root-seal', self.events)
            self.assertFalse(any(c[-1] in ('webservices.target', 'podman.socket') for c in self.start_commands()))
            self.intent['phase'] = 'active'
            self.save_intent()

    def test_login_barrier_descriptor_read_aba_and_parent_replacement_races_are_refused(self):
        for drift in ('file-aba', 'parent-replacement'):
            self.canonical_lifecycle()
            path = self.install_login_barrier_fixture()
            original = os.pread
            changed = False
            def race(fd, count, offset):
                nonlocal changed
                data = original(fd, count, offset)
                if not changed and self.fds[fd] == path:
                    changed = True
                    if drift == 'file-aba':
                        old = path.stat()
                        self.write(path, b'# transient body\n'); self.write(path, m.LOGIN_BARRIER_BODY)
                        os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns + 1))
                    else:
                        path.parent.rename(path.parent.with_name('displaced-vendor'))
                        self.write(path, m.LOGIN_BARRIER_BODY)
                return data
            with patch.object(m.os, 'pread', side_effect=race):
                with self.assertRaisesRegex(ValueError, 'CAS changed'):
                    m.manager_state(self.uid)
            if drift == 'parent-replacement':
                # Both are isolated temp directories; no ownership recovery.
                path.unlink(); path.parent.rmdir()
                path.parent.with_name('displaced-vendor').rename(path.parent)

    def test_canonical_start_refuses_failed_boot_other_login_and_unknown_manager_scope(self):
        for changes, sessions in (({'ActiveState': 'failed', 'SubState': 'failed'}, []),
                                  ({'MainPID': '9'}, []), ({'Job': '77'}, []),
                                  ({'FragmentPath': '/foreign/user@.service'}, []),
                                  ({'DropInPaths': '/etc/override.conf'}, []),
                                  ({}, [{'uid': self.uid, 'session': '44'}]),
                                  ({}, [{'uid': 'unknown', 'session': '44'}])):
            with self.subTest(changes=changes, sessions=sessions):
                self.canonical_lifecycle()
                self.manager.update(changes)
                self.sessions = sessions
                proof = self.verify()
                with self.assertRaises(ValueError):
                    self.op('start', proof)
                self.assertEqual(self.start_commands(), [])
                self.intent['phase'] = 'active'
                self.save_intent()

    def test_canonical_start_manager_timeout_and_failed_boot_never_start_apps(self):
        for outcome in ('pending', 'failed'):
            with self.subTest(outcome=outcome):
                proof = self.canonical_lifecycle()
                self.manager_outcome = outcome
                with self.assertRaises(ValueError):
                    self.op('start', proof)
                self.assertEqual([c[-1] for c in self.start_commands()], ['user@780.service'])
                self.assertEqual(m.load(self.root / '.install-intent.json', private=True)['phase'], 'failed')
                self.commands.clear()
                self.intent['phase'] = 'active'
                self.save_intent()

    def test_canonical_start_manager_pid_or_boot_drift_refuses_before_app_activation(self):
        for drift in ('pid', 'boot', 'fragment', 'source'):
            with self.subTest(drift=drift):
                proof = self.canonical_lifecycle()
                original = self.runtime.verify_prepared_units
                def changed(root, release, intent):
                    result = original(root, release, intent)
                    if self.manager['ActiveState'] == 'active':
                        if drift == 'pid' and self.managed_seen:
                            self.manager['MainPID'] = '9999'
                        elif drift == 'boot':
                            self.write(self.map_path('/proc/sys/kernel/random/boot_id'), 'ffffffff-1234-1234-1234-123456789abc\n')
                        elif drift == 'fragment' and self.managed_seen:
                            self.write(self.map_path('/run/user/780/systemd/generator/webservices-app.service'), 'changed\n')
                        elif drift == 'source':
                            result = dict(result, sourceSha256='c' * 64)
                        self.managed_seen = True
                    return result
                self.managed_seen = False
                self.runtime.verify_prepared_units = changed
                with self.assertRaises(ValueError):
                    self.op('start', proof)
                self.assertFalse(any(c[-1] in ('webservices.target', 'podman.socket') for c in self.start_commands()))
                self.commands.clear()
                self.intent['phase'] = 'active'
                self.save_intent()

    def test_canonical_root_copy_observation_must_be_fresh_complete_and_non_authorizing(self):
        for key, value in (('bootId', 'previous-boot'), ('copies', {}), ('release', '/retired'),
                           ('intentSha256', 'stale'), ('activationAuthorized', True), ('journalWritten', True)):
            with self.subTest(key=key):
                proof = self.canonical_lifecycle()
                seal = self.runtime.seal_running_copies
                self.runtime.seal_running_copies = lambda *args: dict(seal(*args), **{key: value})
                with self.assertRaises(ValueError):
                    self.op('start', proof)
                self.assertFalse(any(c[-1] in ('webservices.target', 'podman.socket') for c in self.start_commands()))
                self.commands.clear()
                self.intent['phase'] = 'active'
                self.save_intent()

    def test_canonical_source_api_missing_and_offline_namespace_race_never_bootstrap(self):
        proof = self.canonical_lifecycle()
        del self.runtime.verify_prepared_units
        with self.assertRaisesRegex(ValueError, 'observation API unavailable'):
            self.op('start', proof)
        self.assertEqual(self.start_commands(), [])
        self.intent['phase'] = 'active'
        self.save_intent()
        proof = self.canonical_lifecycle()
        self.offline_verify.side_effect = ValueError('mapped namespace appeared')
        with self.assertRaises(ValueError):
            self.op('start', proof)
        self.assertEqual(self.start_commands(), [])

    def test_canonical_root_issuer_cue_transition_never_rebases_source_or_adopts_actor_cue(self):
        for drift in ('source-at-seal', 'foreign-issued-cue', 'actor-cue-before-seal'):
            with self.subTest(drift=drift):
                proof = self.canonical_lifecycle()
                original = self.runtime.seal_running_copies
                if drift == 'actor-cue-before-seal':
                    def changed(command):
                        if command[-1] == 'user@780.service':
                            self.copy_cues['rootless-apps'] = {'actorStamp': True}
                    self.lifecycle_hook = changed
                else:
                    def changed(*args):
                        result = original(*args)
                        if drift == 'source-at-seal':
                            self.source_sha = 'e' * 64
                        else:
                            result['copies']['rootless-apps']['receipt'] = {'foreignCue': True}
                        return result
                    self.runtime.seal_running_copies = changed
                with self.assertRaises(ValueError):
                    self.op('start', proof)
                self.assertFalse(any(c[-1] in ('webservices.target', 'podman.socket') for c in self.start_commands()))
                self.intent['phase'] = 'active'
                self.save_intent()

    def test_canonical_running_manager_start_uses_same_exact_source_and_fresh_root_copy_seal(self):
        self.canonical_lifecycle()
        self.manager.update(ActiveState='active', SubState='running', MainPID='4321',
            ControlGroup='/user.slice/user-780.slice/user@780.service')
        proof = self.verify()
        result = self.op('start', proof)
        self.assertTrue(result['nativeHealthy'])
        self.assertNotIn('user@780.service', [c[-1] for c in self.start_commands()])
        self.assertIn('root-seal', self.events)
        self.assertEqual(proof['planSha256'], result['planSha256'])

    def test_canonical_foreign_enabled_boot_unit_refuses_before_manager_dispatch(self):
        proof = self.canonical_lifecycle()
        self.enabled_boot_units = 'foreign.service enabled enabled\n'
        with self.assertRaisesRegex(ValueError, 'enabled actor boot units'):
            self.op('start', proof)
        self.assertEqual(self.start_commands(), [])

    def test_canonical_boot_closure_foreign_dependency_override_and_race_refuse(self):
        for drift in ('foreign', 'override', 'later'):
            with self.subTest(drift=drift):
                proof = self.canonical_lifecycle()
                if drift == 'foreign':
                    self.boot_rows['default.target']['Wants'] = 'unselected.service'
                elif drift == 'override':
                    self.boot_rows['basic.target']['DropInPaths'] = '/foreign/override.conf'
                else:
                    original = self.runtime.verify_prepared_units
                    def changed(*args):
                        observed = original(*args)
                        if 'webservices-runtime-env.service' in self.events:
                            self.boot_rows['default.target']['Wants'] = 'unselected.service'
                        return observed
                    self.runtime.verify_prepared_units = changed
                with self.assertRaises(ValueError):
                    self.op('start', proof)
                self.assertFalse(any(c[-1] in ('webservices.target', 'podman.socket') for c in self.start_commands()))
                self.intent['phase'] = 'active'
                self.save_intent()

    def test_native_updater_artifacts_never_grant_installed_or_stop_ownership(self):
        proof = self.canonical_lifecycle()
        plans = m.snapshot(self.root, self.journal)[3]
        self.assertTrue(all(not set(plan['units']).intersection(m.LEGACY_UPDATERS) for plan in plans))
        for name in m.LEGACY_UPDATERS:
            self.assertTrue((self.release / 'ops' / name).is_file())
        result = self.op('stop', proof)
        self.assertTrue(result['nativeStopped'])
        self.assertFalse(any(name in command for command in self.mutations() for name in m.LEGACY_UPDATERS))

    def test_native_foreign_updater_file_wrapper_and_live_state_never_adopted_or_touched(self):
        for occupant in ('unit', 'wrapper', 'live'):
            with self.subTest(occupant=occupant):
                self.canonical_lifecycle()
                if occupant == 'unit':
                    path = self.map_path('/etc/systemd/system/webservices-auto-update.timer')
                    self.write(path, '[Timer]\nOnBootSec=1\n')
                elif occupant == 'wrapper':
                    path = self.map_path('/usr/local/sbin/webservices-auto-update')
                    self.write(path, '# synthetic foreign authored wrapper\n')
                else:
                    path = None
                    self.updater_probe['webservices-auto-update.service'].update(LoadState='loaded', ActiveState='active',
                        FragmentPath='/usr/lib/systemd/system/webservices-auto-update.service')
                self.commands.clear()
                for action in ('verify', 'stop', 'start'):
                    with self.assertRaises(ValueError):
                        m.operate(action, self.root, {}, self.journal, wait_seconds=0)
                self.assertEqual(self.start_commands(), [])
                self.assertFalse(any('stop' in c or 'disable' in c for c in self.commands))
                if path is not None:
                    self.assertTrue(path.exists())
                    path.unlink()

    def test_canonical_boot_must_not_autoactivate_selected_apps_or_api_before_root_seal(self):
        proof = self.canonical_lifecycle()
        def autoactivated(command):
            if command[-1] == 'user@780.service':
                self.rows['rootless-apps']['webservices-app.service']['ActiveState'] = 'active'
        self.lifecycle_hook = autoactivated
        with self.assertRaisesRegex(ValueError, 'auto-activated'):
            self.op('start', proof)
        self.assertNotIn('root-seal', self.events)
        self.assertFalse(any(c[-1] in ('webservices.target', 'podman.socket') for c in self.start_commands()))

    def test_canonical_fd9_never_overwrites_an_occupied_caller_descriptor(self):
        with patch.object(m.fcntl, 'fcntl', return_value=10) as allocate, patch.object(m.os, 'close') as close:
            with self.assertRaisesRegex(ValueError, 'FD9 occupied'):
                with m.canonical_lock_fd(123):
                    self.fail('occupied FD9 was adopted')
        allocate.assert_called_once_with(123, m.fcntl.F_DUPFD_CLOEXEC, 9)
        close.assert_called_once_with(10)

    def test_runtime_api_requires_full_selected_ops_hashes_and_refuses_unknown_closure(self):
        loader = m.runtime_api
        for name in ('webservices-auto-update.timer', 'webservices-auto-update.service'):
            # These are already emitted into this synthetic release's ops set.
            self.assertTrue((self.release / 'ops' / name).is_file())
        helper = self.release / 'ops/native-runtime-env-units.py'
        self.write(helper, 'def render_unit(manifest):\n    return b"synthetic reviewed source"\n')
        pins = {'ops/' + p.name: m.sha(p.read_bytes()) for p in (self.release / 'ops').iterdir()}
        self.write(self.release / 'bundle.json', {'schemaVersion': 1, 'liveOps': pins})
        self.assertEqual(loader(self.release).render_unit({}), b'synthetic reviewed source')
        self.write(helper, 'raise AssertionError("unsealed source executed")\n')
        with self.assertRaisesRegex(ValueError, 'source drift'):
            loader(self.release)
        self.write(helper, 'def render_unit(manifest):\n    return b"synthetic reviewed source"\n')
        unknown = self.release / 'ops/unpinned-helper.py'
        self.write(unknown, '# must not import\n')
        with self.assertRaisesRegex(ValueError, 'Unpinned'):
            loader(self.release)
        unknown.unlink()
        for invalid in ({}, {'ops/../escape.py': '0' * 64}, {'ops/native-runtime-env-units.py': 'NOT-A-HASH'}):
            self.write(self.release / 'bundle.json', {'liveOps': invalid})
            with self.assertRaises(ValueError):
                loader(self.release)
        self.assertEqual(self.mutations(), [])

    def test_real_selected_runtime_renderer_is_used_instead_of_legacy_installer_template(self):
        # Import actual SOURCE from a completely temp, pinned ops closure. Only
        # pure render APIs are called; this is NOT installed/runtime proof.
        source = m.ROOT / 'runtime-generator/podman-ops'
        for path in source.iterdir():
            if path.is_file() and not path.is_symlink():
                self.write(self.release / 'ops' / path.name, path.read_bytes())
        self.omit_native_updaters()
        pins = {'ops/' + path.name: m.sha(path.read_bytes()) for path in (self.release / 'ops').iterdir()}
        self.write(self.release / 'bundle.json', {'schemaVersion': 1, 'liveOps': pins})
        api = m.runtime_api(self.release)
        self.assertTrue(callable(api.verify_prepared_units))
        self.assertTrue(callable(api.seal_running_copies))
        custody = {'roles': {p['role']: {'role': p['role'], 'release': str(self.release)} for p in self.plan}}
        self.intent['nativeRuntimeEnvUnitCustody'] = custody
        self.intent['inputs'] = self.journal.fingerprint(self.release)
        self.save_intent()
        for plan in self.plan:
            folder = Path(plan['units']['webservices-runtime-env.service']['sourcePath']).parent
            data = api.render_unit(custody['roles'][plan['role']])
            self.assertIn(b'Restore exact selected webservices environment files', data)
            self.assertIn(b'ExecStart=/usr/bin/python3 -I -B', data)
            self.assertNotIn(b'for env_file in ', data)
            self.write(folder / 'webservices-runtime-env.service', data)
            self.write(folder / 'webservices.target.d/10-runtime-env.conf', api.render_dropin())
            self.rows[plan['role']]['webservices.target']['DropInPaths'] = str(folder / 'webservices.target.d/10-runtime-env.conf')
        self.assertTrue(self.verify()['nativeHealthy'])
        runtime = self.map_path('/home/' + self.user + '/.config/systemd/user/webservices-runtime-env.service')
        self.write(runtime, runtime.read_bytes() + b'# unreceipted edit\n')
        with self.assertRaisesRegex(ValueError, 'canonical selected source'):
            self.verify()
        self.assertEqual(self.mutations(), [])

    def test_runtime_api_ops_symlink_and_foreign_owner_refused_before_import(self):
        helper = self.release / 'ops/native-runtime-env-units.py'
        data = b'raise AssertionError("foreign source executed")\n'
        self.write(helper, data)
        pins = {'ops/' + p.name: m.sha(p.read_bytes()) for p in (self.release / 'ops').iterdir()}
        self.write(self.release / 'bundle.json', {'liveOps': pins})
        self.owner_overrides[helper] = self.uid
        with self.assertRaises(ValueError):
            m.runtime_api(self.release)
        self.owner_overrides.pop(helper)
        outside = self.base / 'foreign.py'
        self.write(outside, data)
        helper.unlink()
        helper.symlink_to(outside)
        with self.assertRaises((OSError, ValueError)):
            m.runtime_api(self.release)
        self.assertEqual(self.mutations(), [])

    def test_offline_trigger_process_subrange_or_manager_drift_fails_closed(self):
        self.set_offline()
        proof = self.verify()
        for reason in ('linger trigger', 'API trigger', 'own process', 'mapped process', 'manager job'):
            self.offline_verify.side_effect = ValueError(reason)
            with self.assertRaises(ValueError):
                self.op('stop', proof)
        self.offline_verify.side_effect = None
        self.offline.side_effect = ValueError('pending manager state')
        with self.assertRaises(ValueError):
            self.verify()
        self.assertEqual(self.mutations(), [])
        self.journal_write.assert_not_called()

    def test_offline_manager_transition_invalidates_cas_before_any_dispatch(self):
        self.set_offline()
        proof = self.verify()
        self.offline.side_effect = None
        self.offline.return_value = None
        with self.assertRaises(ValueError):
            self.op('stop', proof)
        self.assertEqual(self.mutations(), [])

    def test_offline_proof_identity_and_source_cannot_be_borrowed(self):
        actor = self.set_offline()
        actor['uid'] += 1
        with self.assertRaises(ValueError):
            self.verify()
        actor['uid'] -= 1
        path = self.map_path('/home/' + self.user + '/.config/containers/systemd/webservices-app.container')
        self.write(path, '[Container]\nImage=foreign\n')
        with self.assertRaises(ValueError):
            self.verify()
        self.assertFalse(any('--user' in cmd for cmd in self.commands))

    def test_masked_live_unit_not_adopted_as_selected_source(self):
        row = self.rows['rootless-apps']['webservices-app.service']
        row.update(LoadState='masked', FragmentPath='/dev/null', UnitFileState='masked')
        with self.assertRaises(ValueError):
            self.verify()
        self.assertEqual(self.mutations(), [])

    def test_acl_reader_binds_fd_rejects_default_duplicate_and_effective_mask(self):
        # Exercise the saved real parser, not the fixture ACL adapter.
        parser = REAL_ACL_ENTRIES
        with patch.object(m.subprocess, 'run') as command:
            command.return_value = SimpleNamespace(returncode=0, stdout='user::rwx\ngroup::rwx\nother::---\n')
            self.assertEqual(parser(17)[('other', '')], '---')
            self.assertEqual(command.call_args.kwargs['pass_fds'], (17,))
            self.assertEqual(command.call_args.args[0][-1], '/proc/self/fd/17')
            for text in ('user::rwx\nuser::rwx\n', 'default:user::rwx\n',
                         'user:780:rwx\t#effective:--x\n'):
                command.return_value.stdout = text
                with self.assertRaises(ValueError):
                    parser(17)

    def test_cli_requires_explicit_cas_and_distinct_verify_exit_code(self):
        with contextlib.redirect_stderr(__import__('io').StringIO()):
            with self.assertRaises(SystemExit) as error:
                m.main(['start', '--state-root', str(self.root)])
        self.assertEqual(error.exception.code, 2)
        with patch.object(m, 'operate', return_value={'nativeHealthy': False}) as operation, \
             contextlib.redirect_stdout(__import__('io').StringIO()):
            self.assertEqual(m.main(['verify', '--state-root', str(self.root)]), 1)
            self.assertEqual(operation.call_args.args[0], 'verify')


class PublicDispatch(unittest.TestCase):
    def test_public_native_actions_reach_exact_backend_argument_parser(self):
        script = SOURCE.parents[1] / 'stackctl.sh'
        for action in ('start', 'stop', 'verify'):
            with self.subTest(action=action):
                result = subprocess.run(['bash', str(script), action, '--help'],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('--state-root', result.stdout)
                if action != 'verify':
                    self.assertIn('--expected-intent-sha256', result.stdout)
                    self.assertIn('--expected-receipt-sha256', result.stdout)
                    self.assertIn('--expected-plan-sha256', result.stdout)


if __name__ == '__main__':
    unittest.main()
