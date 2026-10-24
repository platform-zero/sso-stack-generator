#!/usr/bin/env python3
"""Bounded isolated source proof ONLY; real FD deletion/locks in local temp roots.

All ownership, accounts, ACLs, process/mount/native state are modeled. Subprocess
execution is forbidden. No privileged calls, host /proc query, network, package,
key/store/environment access, native install, or deployed acceptance. 0/2.
"""
import contextlib
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
from unittest.mock import patch

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]
OPS = REPO / 'runtime-generator/podman-ops'
spec = importlib.util.spec_from_file_location('clean_reset_subject', OPS / 'host-clean-reset.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
REAL_STAT, REAL_FSTAT, REAL_LSTAT, REAL_OPEN = os.stat, os.fstat, Path.lstat, os.open
REAL_DIRECTORY, REAL_STOPPED = m.directory, m.stopped
REAL_ALLOCATION = m.allocation_authority
REAL_COLD_CALL, REAL_COLD_PATH, REAL_CONTEXT = m.cold_call, m.cold_path, m.default_context
REAL_LAYERS, REAL_BRIDGE = m.layer_inventory, m.bridge_state
REAL_ROOT_RUNTIME = m.root_runtime_identity


class ModelStat:
    def __init__(self, original, uid, gid, mode=None):
        self.original = original
        self.st_uid, self.st_gid = uid, gid
        self.st_mode = original.st_mode if mode is None else mode
    def __getattr__(self, name): return getattr(self.original, name)


class Clean(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='.clean-reset-fixture-', dir=REPO)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name); self.owners = {}; self.acls = {}; self.defaults = {}
        self.root = self.base / 'metadata'; self.root.mkdir(mode=0o700)
        self.release = self.root / 'releases/r1'; self.release.mkdir(parents=True, mode=0o700)
        self.release.parent.chmod(0o700)
        self.shared = self.base / 'stack'; self.shared.mkdir(); self.shared.chmod(0o2775)
        self.scope = self.shared / 'host-stack-lab'; self.scope.mkdir(); self.scope.chmod(0o2770)
        (self.root / '.install.lock').touch(mode=0o600)
        self.virtual = self.base / 'virtual'; self.virtual.mkdir()
        for name in ('etc', 'home', 'run', 'usr'): (self.virtual / name).mkdir()
        for path in ('etc/systemd/system', 'etc/containers/systemd', 'run/user', 'usr/local/sbin'):
            (self.virtual / path).mkdir(parents=True, exist_ok=True)
        self.patch(m, 'SCOPE', new=self.scope); self.patch(m, 'SHARED', new=self.shared)
        self.rows = []; self.actors = []
        for index, (name, (uid, user)) in enumerate(m.IDENTITIES.items()):
            row = {'name': name, 'uid': uid, 'user': user, 'subuidStart': 2000000 + index * 65536,
                   'services': [], 'persistentServices': [], 'metadataSource': 'podman-domains.json'}
            actor = {'name': name, 'uid': uid, 'gid': uid, 'user': user, 'start': row['subuidStart'],
                     'count': 65536, 'home': '/home/' + user}
            for key, directory in zip(m.ROOTS, ('state', 'graphs', 'volumes')):
                path = self.scope / directory / name
                path.mkdir(parents=True, mode=0o700); path.chmod(0o700); self.own(path, uid, uid)
                row[key] = str(path)
            self.rows.append(row); self.actors.append(actor)
            home = self.physical(Path(actor['home'])); home.mkdir()
            for directory in ('.config/containers/systemd', '.config/systemd/user/webservices.target.d'):
                (home / directory).mkdir(parents=True, exist_ok=True)
            # Canonical fixture profile must not inherit the caller's umask077.
            (home / '.config/systemd/user/webservices.target.d').chmod(0o755)
            self.own(home / '.config/systemd/user/webservices.target.d', actor['uid'], actor['gid'])
        self.ids = {entry[key] for entry in self.actors for key in ('uid', 'start')}
        self.own(self.shared, 1000, 1000); self.own(self.scope, 1000, 1000)
        self.set_acl(self.shared, m.expected_acl(True, self.ids), m.expected_acl(True, default=True))
        self.set_acl(self.scope, m.expected_acl(False, self.ids), m.expected_acl(False, default=True))
        for name in ('state', 'graphs'):
            path = self.scope / name; path.chmod(0o700)
        volumes = self.scope / 'volumes'; volumes.chmod(0o755); self.own(volumes, 0, 1000)
        volume_acl = [[1, 7, m.UNDEFINED], [2, 7, 1000], [4, 5, m.UNDEFINED],
                      [8, 7, 1000], [16, 5, m.UNDEFINED], [32, 5, m.UNDEFINED]]
        volume_acl += [[2, 1, value] for value in self.ids]
        self.set_acl(volumes, sorted(volume_acl))
        self.manifest = {'site': 'synthetic-test', 'deploymentMode': 'standalone', 'installerStateRoot': str(self.root),
                         'storageScope': {'root': str(self.scope), 'dataClass': 'synthetic'}}
        self.metadata = {'schemaVersion': 1, 'deploymentMode': 'standalone', 'installerStateRoot': str(self.root),
                         'storageScope': self.manifest['storageScope'], 'domains': self.rows}
        self.ir = {'schemaVersion': 1, 'services': {'edge': {'placement': 'rootful', 'lifecycle': 'daemon',
                   'target': 'core', 'image': 'sha256:' + 'a' * 64}}, 'volumes': {}, 'networks': {}}
        self.emit_units()
        fixture_recognized = copy.deepcopy(m.RECOGNIZED)
        for name in m.RECOGNIZED:
            digest = self.put(self.release / 'ops' / name, (OPS / name).read_bytes())
            # Shared journal source may be under concurrent integration. Model
            # only this isolated copy as reviewed; NEVER expand production pins.
            fixture_recognized[name].add(digest)
        self.patch(m, 'RECOGNIZED', new=fixture_recognized)
        # Explicit model of a legacy-owning installer generation. Never execute
        # the mutable workspace installer or claim its modeled hash is deployed.
        self.patch(m, 'LEGACY_SOURCE_INSTALLERS', new=frozenset(fixture_recognized['install-podman-bundle.sh']))
        # Canonical donor is a protected modeled sibling of the backend's own
        # __file__, never a caller argument/receipt/environment discovery path.
        self.canonical_ops = self.base / 'canonical-tool/ops'
        self.put(self.canonical_ops / 'host-clean-reset.py', (OPS / 'host-clean-reset.py').read_bytes())
        self.put(self.canonical_ops / 'native-selection.py', (OPS / 'native-selection.py').read_bytes())
        self.patch(m, '__file__', new=str(self.canonical_ops / 'host-clean-reset.py'))
        for name in ('webservices-auto-update.timer', 'webservices-auto-update.service', 'webservices-auto-update'):
            self.put(self.release / 'ops' / name, (OPS / name).read_bytes())
        self.receipt_extra = {}; self.optional_inputs = {}; self.seal()
        (self.root / 'current').symlink_to(self.release)
        self.original_intent = (self.root / '.install-intent.json').read_bytes()
        self.populate()
        self.outside = self.shared / 'original-private-cache'; self.outside.mkdir()
        self.put(self.outside / 'keep', b'synthetic outsider must survive')
        self.operator_key = self.base / 'retained-operator-age-key'; self.put(self.operator_key, b'synthetic retained infrastructure')
        ancestor_stats = {self.key(path): REAL_LSTAT(path) for path in self.base.parents}
        self.ancestor_inodes = set(ancestor_stats)
        def model(info):
            key = (info.st_dev, info.st_ino)
            uid, gid = self.owners.get(key, (0, 0))
            mode = info.st_mode & ~0o022 if key in self.ancestor_inodes else info.st_mode
            result = ModelStat(info, uid, gid, mode)
            if key in ancestor_stats:
                # Model the sealed ancestry ABOVE this isolated temp fixture.
                # Other workers creating sibling repo fixtures must not create
                # nondeterministic source CAS failures. Every inode, timestamp,
                # mode, link and mutation INSIDE our fixture remains real.
                for field in ('st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'):
                    setattr(result, field, getattr(ancestor_stats[key], field))
            return result
        # Plain replacements avoid retaining millions of Mock call objects in
        # the repeated FD/CAS walk; keep the same real temp-inode checks.
        self.patch(m.os, 'stat', new=lambda *a, **kw: model(REAL_STAT(*a, **kw)))
        self.patch(m.os, 'fstat', new=lambda *a, **kw: model(REAL_FSTAT(*a, **kw)))
        self.patch(Path, 'lstat', new=lambda path, *a, **kw: model(REAL_LSTAT(path, *a, **kw)))
        self.patch(m.os, 'geteuid', return_value=0)
        def opened(path, flags, *args, **kwargs):
            fd = REAL_OPEN(path, flags, *args, **kwargs)
            if flags & os.O_CREAT and flags & os.O_EXCL:
                # Fresh root evidence inodes can reuse previously deleted actor
                # inode numbers; model creation, not stale inode-map ownership.
                key = self.key_fd(fd); self.owners[key] = (0, 0)
                self.acls.pop(key, None); self.defaults.pop(key, None)
            return fd
        self.patch(m.os, 'open', new=opened)
        self.patch(m, 'acl', new=lambda fd, default=False: copy.deepcopy(
            (self.defaults if default else self.acls).get(self.key_fd(fd), [])))
        self.patch(m, 'allocation_authority', new=self.allocations)
        self.patch(m, 'stopped', new=self.fake_stopped)
        self.patch(m, 'mount_views', new=self.mounts)
        self.patch(m, 'directory', new=self.virtual_directory)
        self.patch(m.subprocess, 'run', side_effect=AssertionError('Native subprocess forbidden in source fixture'))
        self.patch(m, 'process_statuses', side_effect=AssertionError('Host process query forbidden'))
        self.patch(m, 'fd9_lock', side_effect=AssertionError('Host fdinfo query forbidden'))
        self.native_calls = 0; self.stop_failure = False
        self.engine = {'images': ['a' * 64], 'layers': ['b' * 64], 'orphanLayers': [], 'orphanImageDirs': [], 'containers': [], 'volumes': [],
                       'buildah': [], 'networks': {}, 'pruneFails': False, 'leaveLayers': False,
                       'leaveBridge': False, 'rmFails': False}
        self.cold_calls = []
        self.buildah_info = {'store': {'GraphRoot': m.ROOT_GRAPH, 'RunRoot': m.ROOT_RUN, 'GraphDriverName': 'overlay'}}
        self.root_context = {'controls': {'system': {'sha256': 'c' * 64}},
                             'storageConfigs': {'/usr/share/containers/storage.conf': {'sha256': 'c' * 64}}}
        self.engine_info = {'store': {'graphRoot': m.ROOT_GRAPH, 'runRoot': m.ROOT_RUN,
            'graphDriverName': 'overlay', 'configFile': '/usr/share/containers/storage.conf',
            'volumePath': m.ROOT_GRAPH + '/volumes'}, 'host': {'security': {'rootless': False}, 'networkBackend': 'netavark'}}
        self.patch(m, 'default_context', new=lambda: copy.deepcopy(self.root_context))
        self.patch(m, 'root_runtime_identity', new=lambda: {'user': 'user:[model0]', 'net': 'net:[model0]'})
        self.patch(m, 'layer_inventory', new=lambda: {'ids': list(self.engine['layers']),
            'control': {'sha256': m.sha(m.canonical({'ids': self.engine['layers']}))},
            'disk': {'layers': sorted(set(self.engine['layers'] + self.engine['orphanLayers'])), 'lowerLinks': {}},
            'imageDirectories': {'ids': list(self.engine['orphanImageDirs'])}})
        self.patch(m, 'cold_call', new=self.engine_call)
        self.patch(m.socket, 'if_nametoindex', new=self.interface_index)
        # Explicit temp fixture modes, independent of the caller's umask. Do
        # not change modeled deliberate scope/private-root modes or production.
        selected = {self.shared, self.scope, *(Path(row[key]) for row in self.rows for key in m.ROOTS)}
        for path in self.base.rglob('*'):
            if path.is_dir() and path not in selected:
                path.chmod(stat.S_IMODE(REAL_STAT(path).st_mode) & ~0o022)

    def patch(self, obj, name, **kwargs):
        item = patch.object(obj, name, **kwargs); result = item.start(); self.addCleanup(item.stop); return result

    def key(self, path):
        info = REAL_STAT(path, follow_symlinks=False); return info.st_dev, info.st_ino

    def key_fd(self, fd):
        info = REAL_FSTAT(fd); return info.st_dev, info.st_ino

    def own(self, path, uid, gid=None): self.owners[self.key(path)] = (uid, uid if gid is None else gid)

    def set_acl(self, path, access, default=None):
        self.acls[self.key(path)] = access
        self.defaults[self.key(path)] = default or []

    def physical(self, path):
        if path.is_relative_to(self.base): return path
        if any(path.is_relative_to(root) for root in ('/etc', '/home', '/run', '/usr', '/var/lib/containers')):
            return self.virtual / str(path).lstrip('/')
        return path

    @contextlib.contextmanager
    def virtual_directory(self, path, policies=None):
        with REAL_DIRECTORY(self.physical(path), {self.physical(key): value for key, value in (policies or {}).items()}) as fd:
            yield fd

    def put(self, path, body, mode=0o644):
        missing = []; parent = path.parent
        while not parent.exists(): missing.append(parent); parent = parent.parent
        path.parent.mkdir(parents=True, exist_ok=True)
        for parent in missing: parent.chmod(0o755)
        path.write_bytes(m.canonical(body) if isinstance(body, dict) else body)
        path.chmod(mode)
        return m.sha(path.read_bytes())

    def allocations(self, rows):
        self.assertEqual({row['name'] for row in rows}, set(m.IDENTITIES))
        return {'files': {'subuid': {'sha256': '1' * 64}, 'subgid': {'sha256': '2' * 64}},
                'actors': copy.deepcopy(self.actors), 'operator': {'uid': 1000, 'gid': 1000, 'name': 'operator'}}

    def emit_units(self):
        for label in ['rootful', *['rootless-' + row['name'] for row in self.rows]]:
            base = self.release / 'quadlet' / label
            for target in ('core', 'apps', 'observability'):
                units = 'webservices-edge.service' if label == 'rootful' and target == 'core' else ''
                self.put(base / ('webservices-' + target + '.target'),
                         ('[Unit]\nPartOf=webservices.target\nWants=' + units + '\n[Install]\nWantedBy=webservices.target\n').encode())
            self.put(base / 'webservices.target',
                     ('[Unit]\nWants=webservices-core.target webservices-apps.target webservices-observability.target\n'
                      '[Install]\nWantedBy=' + ('multi-user.target' if label == 'rootful' else 'default.target') + '\n').encode())
        self.put(self.release / 'quadlet/rootful/webservices-edge.container',
                 ('[Unit]\nPartOf=webservices-core.target\n[Container]\nContainerName=edge\nImage=sha256:' + 'a' * 64 +
                  '\n[Service]\n[Install]\nWantedBy=webservices-core.target\n').encode())

    def seal(self, phase='retired-failed'):
        pins = {}
        pins['stack.ir.json'] = self.put(self.release / 'stack.ir.json', self.ir)
        pins['podman-domains.json'] = self.put(self.release / 'podman-domains.json', self.metadata)
        pins['site/manifest.json'] = self.put(self.release / 'site/manifest.json', self.manifest)
        pins['source-provenance.json'] = self.put(self.release / 'source-provenance.json',
            {'manifestSha256': pins['site/manifest.json'], 'generatorCommit': 'd' * 40})
        pins['bundle.json'] = self.put(self.release / 'bundle.json', {'backend': 'podman',
            'irSha256': pins['stack.ir.json'], 'sourceProvenanceSha256': pins['source-provenance.json'], **getattr(self, 'bundle_extra', {})})
        pins.update(self.optional_inputs)
        receipt = {'schemaVersion': 1, 'phase': phase, 'release': str(self.release), 'inputs': pins,
                   'steps': ['preparing', 'failed', 'retired-failed'], **self.receipt_extra}
        self.intent = self.put(self.root / '.install-intent.json', receipt, 0o600)
        self.put(self.release / 'installation-receipt.json', receipt, 0o600)
        marker_rows = [{key: row[key] for key in ('name', 'user', 'uid') + m.ROOTS} for row in self.rows]
        self.put(self.scope / m.MARKER, {'schemaVersion': 1, 'kind': 'standalone-stack-storage',
            'site': self.manifest['site'], 'scope': self.manifest['storageScope'],
            'domains': sorted(marker_rows, key=lambda row: row['name']),
            'roots': sorted(row[key] for row in self.rows for key in m.ROOTS)}, 0o600)

    def populate(self):
        for row, actor in zip(self.rows, self.actors):
            state = Path(row['stateRoot']); graph = Path(row['graphRoot']); volume = Path(row['volumeRoot'])
            self.put(state / 'runtime/config', b'synthetic runtime'); self.own(state / 'runtime', actor['uid'])
            self.own(state / 'runtime/config', actor['uid'])
            self.put(graph / 'overlay/layer/data', b'synthetic image layer')
            for path in (graph / 'overlay', graph / 'overlay/layer', graph / 'overlay/layer/data'):
                self.own(path, actor['start'] + 32)
            self.put(graph / 'volumes/huly-owned/_data/records', b'synthetic podman managed Huly data')
            for path in (graph / 'volumes', graph / 'volumes/huly-owned', graph / 'volumes/huly-owned/_data',
                         graph / 'volumes/huly-owned/_data/records'): self.own(path, actor['uid'])
            self.put(volume / 'app/database', b'synthetic DB'); self.own(volume / 'app', actor['uid'])
            self.own(volume / 'app/database', actor['start'] + 10)
        self.put(self.scope / 'owned-scratch/cache', b'synthetic temporary artifact')

    def fake_stopped(self, selection):
        self.native_calls += 1
        if self.stop_failure: raise m.Refusal('Modeled native stop failure')
        self.assertEqual(set(selection['actors']), set(m.IDENTITIES))

    def mounts(self):
        # No kernel query: filesystem identity is local temp filesystem only.
        dev = REAL_STAT(self.scope).st_dev
        line = f'1 0 {os.major(dev)}:{os.minor(dev)} / / rw - ext4 fixture rw'
        return [[line], [line]]

    def engine_call(self, tool, args, mutate=False):
        self.cold_calls.append((tool, list(args), mutate))
        value = None
        if mutate:
            self.assertEqual(tool, 'podman')
            if args == ['image', 'prune', '--all', '--build-cache', '--force']:
                if self.engine['pruneFails']: return 125, ''
                self.engine['images'] = []
                if not self.engine['leaveLayers']: self.engine['layers'] = []
                return 0, ''
            self.assertEqual(args[:2], ['network', 'rm']); self.assertEqual(len(args), 3)
            if self.engine['rmFails']: return 125, ''
            network = self.engine['networks'][args[2]]
            network['present'] = False
            if not self.engine['leaveBridge']: network['kernel'] = None
            return 0, ''
        if tool == 'podman':
            if args == ['info', '--format=json']: value = self.engine_info
            elif args == ['ps', '--all', '--no-trunc', '--format=json']: value = self.engine['containers']
            elif args == ['volume', 'ls', '--format=json']: value = self.engine['volumes']
            elif args == ['images', '--all', '--no-trunc', '--format=json']: value = [{'Id': item} for item in self.engine['images']]
            elif args == ['network', 'ls', '--format=json']:
                value = [{'name': name} for name, item in self.engine['networks'].items() if item['present']]
            elif args[:2] == ['network', 'exists']:
                return (0 if self.engine['networks'].get(args[2], {}).get('present') else 1), ''
            elif args[:2] == ['network', 'inspect']: value = [self.engine['networks'][args[2]]['inspect']]
            else: self.fail('Unmodeled rootful Podman command')
        elif tool == 'buildah':
            if args == ['info']: value = self.buildah_info
            elif args == ['containers', '--json']: value = self.engine['buildah']
            elif args == ['images', '--all', '--no-trunc', '--json']: value = [{'id': item} for item in self.engine['images']]
            else: self.fail('Unmodeled Buildah command')
        elif tool == 'ip':
            kernels = [row['kernel'] for row in self.engine['networks'].values() if row['kernel'] is not None]
            if args == ['-j', '-d', 'link', 'show']:
                return 0, json.dumps([row['link'] for row in kernels])
            if args == ['-j', 'address', 'show']:
                return 0, json.dumps([address for row in kernels for address in row['addresses']])
            if args == ['-j', 'route', 'show', 'table', 'all']:
                return 0, json.dumps([route for row in kernels for route in row['routes']])
            if args == ['-j', '-6', 'route', 'show', 'table', 'all']:
                return 0, json.dumps([route for row in kernels for route in row['routes6']])
            name = args[-1]
            network = next(row for row in self.engine['networks'].values() if row['inspect']['network_interface'] == name)
            kernel = network['kernel']; self.assertIsNotNone(kernel)
            if args[:4] == ['-j', '-d', 'link', 'show']: value = [kernel['link']]
            elif args[:4] == ['-j', 'link', 'show', 'master']: value = kernel.get('ports', [])
            elif args[:3] == ['-j', 'address', 'show']: value = kernel['addresses']
            elif '-6' in args: value = kernel['routes6']
            else: value = kernel['routes']
        else: self.fail('Unknown model engine tool')
        return 0, json.dumps(value)

    def interface_index(self, name):
        for network in self.engine['networks'].values():
            if network['inspect']['network_interface'] == name and network['kernel'] is not None:
                return network['kernel']['ifindex']
        raise OSError(19, 'synthetic absent selected interface')

    def add_root_network(self, name='safe', bridge='podman5'):
        self.ir['networks'][name] = {}
        self.ir['services']['edge']['networks'] = [name]
        source = self.release / 'quadlet/rootful/webservices-edge.container'
        source.write_bytes(source.read_bytes().replace(b'[Service]', ('Network=webservices-' + name + '.network\n[Service]').encode()))
        self.put(self.release / ('quadlet/rootful/webservices-' + name + '.network'),
                 ('[Network]\nNetworkName=webservices_' + name + '\n').encode())
        self.seal()
        index = 10 + len(self.engine['networks'])
        kernel = {'ifindex': index, 'link': {'ifindex': index, 'ifname': bridge, 'linkinfo': {'info_kind': 'bridge'}},
                  'addresses': [{'ifindex': index, 'ifname': bridge, 'addr_info': [{'local': '10.20.0.1', 'prefixlen': 24, 'scope': 'global'}]}],
                  'routes': [{'dev': bridge, 'dst': '10.20.0.0/24'}], 'routes6': [], 'ports': []}
        network = {'present': True, 'inspect': {'name': 'webservices_' + name, 'id': m.sha(name.encode()),
            'driver': 'bridge', 'network_interface': bridge, 'subnets': [{'subnet': '10.20.0.0/24', 'gateway': '10.20.0.1'}]}, 'kernel': kernel}
        self.engine['networks']['webservices_' + name] = network
        return network

    def review(self): return m.review(self.root, self.intent)

    def run_reset(self, reviewed=None):
        reviewed = reviewed or self.review()
        lease = m.issue_stopped_lease(self.root, self.intent, reviewed['planSha256'])
        return m.execute(self.root, self.intent, reviewed['planSha256'], lease)

    def denied(self):
        with self.assertRaises((m.Refusal, OSError, ValueError)): self.review()
        self.assertTrue((Path(self.rows[0]['graphRoot']) / 'overlay/layer/data').exists())

    def test_full_scope_clear_keeps_only_pinned_infrastructure(self):
        reviewed = self.review(); self.assertFalse((self.root / '.host-clean-reset').exists())
        result = self.run_reset(reviewed)
        self.assertTrue(result['completeCleanReset']); self.assertEqual(result['countedAcceptance'], '0/2')
        self.assertFalse(result['applicationAcceptance']); self.assertFalse(result['backupCreated'])
        self.assertEqual((self.root / '.install-intent.json').read_bytes(), self.original_intent)
        self.assertEqual((self.release / 'installation-receipt.json').read_bytes(), self.original_intent)
        self.assertEqual((self.outside / 'keep').read_bytes(), b'synthetic outsider must survive')
        self.assertTrue(self.operator_key.exists())
        self.assertFalse((self.scope / 'owned-scratch').exists())
        for row in self.rows:
            for key in m.ROOTS:
                self.assertFalse(Path(row[key]).exists())
        self.assertEqual(result['privateRootsLeftAbsent'], sorted(row[key] for row in self.rows for key in m.ROOTS))
        evidence = list((self.root / '.host-clean-reset').glob('*-intent.json'))
        self.assertEqual(len(evidence), 1)
        self.assertIn('plan', json.loads(evidence[0].read_text()))
        self.assertGreater(self.native_calls, 3)

    def test_scope_parent_mode_and_both_acls_unchanged(self):
        before = (REAL_STAT(self.shared).st_mode, copy.deepcopy(self.acls), copy.deepcopy(self.defaults))
        self.run_reset()
        self.assertEqual(REAL_STAT(self.shared).st_mode, before[0])
        self.assertEqual(self.acls, before[1]); self.assertEqual(self.defaults, before[2])

    def test_internal_layer_hardlinks_supported_across_same_domain_roots(self):
        row = self.rows[0]; source = Path(row['graphRoot']) / 'overlay/layer/data'
        alias = Path(row['stateRoot']) / 'same-domain-layer'; os.link(source, alias)
        self.assertEqual(REAL_STAT(source).st_nlink, 2)
        self.run_reset(); self.assertFalse(source.exists()); self.assertFalse(alias.exists())

    def test_external_hardlink_refused_before_deletion(self):
        source = Path(self.rows[0]['graphRoot']) / 'overlay/layer/data'
        os.link(source, self.outside / 'layer-alias'); self.denied()

    def test_external_hardlink_contents_are_never_read_before_refusal(self):
        source = Path(self.rows[0]['graphRoot']) / 'overlay/layer/data'
        os.link(source, self.outside / 'external-alias')
        forbidden = self.key(source); original = os.read
        def read(fd, count):
            self.assertNotEqual(self.key_fd(fd), forbidden, 'External alias contents must not be hashed')
            return original(fd, count)
        with patch.object(m.os, 'read', side_effect=read): self.denied()

    def test_cross_domain_hardlink_refused_even_root_owned(self):
        source = Path(self.rows[0]['graphRoot']) / 'root-layer'; self.put(source, b'synthetic')
        os.link(source, Path(self.rows[1]['graphRoot']) / 'root-layer'); self.denied()

    def test_hardlinked_symlink_refused(self):
        source = Path(self.rows[0]['graphRoot']) / 'link'; source.symlink_to(self.outside)
        os.link(source, source.parent / 'alias', follow_symlinks=False); self.denied()

    def test_inert_owned_symlink_target_never_followed_or_read(self):
        link = Path(self.rows[0]['graphRoot']) / 'inert'; link.symlink_to(self.outside)
        self.own(link, self.actors[0]['uid'])
        real_readlink = os.readlink
        def readlink(path, *args, **kwargs):
            self.assertNotEqual(str(path), 'inert'); return real_readlink(path, *args, **kwargs)
        with patch.object(m.os, 'readlink', side_effect=readlink): self.run_reset()
        self.assertFalse(link.is_symlink()); self.assertTrue((self.outside / 'keep').exists())

    def test_linked_scope_root_refused(self):
        moved = self.scope.with_name('moved'); self.scope.rename(moved); self.scope.symlink_to(moved)
        with self.assertRaises(OSError): self.review()

    def test_special_fifo_refused(self):
        os.mkfifo(Path(self.rows[0]['stateRoot']) / 'fifo'); self.denied()

    def test_foreign_uid_and_gid_and_cross_domain_mapped_ids_refused(self):
        data = Path(self.rows[0]['graphRoot']) / 'overlay/layer/data'
        for uid, gid in ((999, 0), (0, 999), (self.actors[1]['uid'], 0),
                         (0, self.actors[1]['start']), (1000, 1000)):
            with self.subTest(uid=uid, gid=gid):
                self.own(data, uid, gid); self.denied()

    def test_foreign_scope_temporary_artifact_refused(self):
        self.own(self.scope / 'owned-scratch/cache', 1000, 1000); self.denied()

    def test_foreign_named_data_acl_refused(self):
        data = Path(self.rows[0]['graphRoot']) / 'overlay/layer/data'
        self.set_acl(data, [[2, 1, self.actors[1]['start']]]); self.denied()

    def test_foreign_scope_default_acl_refused(self):
        self.defaults[self.key(self.scope)].append([2, 1, self.actors[0]['uid']]); self.denied()

    def test_public_volume_ancestor_is_valid_without_chmod(self):
        before = REAL_STAT(self.scope / 'volumes').st_mode; self.run_reset()
        self.assertEqual(before, REAL_STAT(self.scope / 'volumes').st_mode)

    def test_root_metadata_755_refused_without_repair(self):
        self.root.chmod(0o755); self.denied(); self.assertEqual(stat.S_IMODE(REAL_STAT(self.root).st_mode), 0o755)

    def test_noncanonical_scope_or_production_refused(self):
        for changed in ({'root': str(self.scope), 'dataClass': 'production'},
                        {'root': str(self.scope / 'other'), 'dataClass': 'synthetic'}):
            self.manifest['storageScope'] = changed; self.metadata['storageScope'] = changed
            self.seal(); self.denied()

    def test_marker_hash_and_receipt_pointer_drift_refused(self):
        marker = self.scope / m.MARKER; marker.write_text('{}'); self.denied(); self.seal()
        pointer = self.root / 'current'; pointer.unlink(); pointer.symlink_to('releases/r1'); self.denied()

    def test_optional_source_hash_and_absence_are_rechecked(self):
        name = 'site/components.lock.json'; path = self.release / name
        self.optional_inputs[name] = self.put(path, {'synthetic': 1}); self.seal()
        self.review(); self.put(path, {'synthetic': 2}); self.denied()
        path.unlink(); self.optional_inputs[name] = None; self.seal(); self.review()
        self.put(path, {'synthetic': 1}); self.denied()

    def test_marker_boolean_schema_is_not_an_integer_identity(self):
        path = self.scope / m.MARKER; marker = json.loads(path.read_text())
        marker['schemaVersion'] = True; self.put(path, marker, 0o600); self.denied()

    def test_source_hash_drift_and_unknown_helper_refused(self):
        helper = self.release / 'ops/install-journal.py'; helper.write_bytes(helper.read_bytes() + b'\n# unrecognized\n')
        self.denied()

    def missing_historical_selection(self):
        (self.release / 'ops/native-selection.py').unlink()
        return self.canonical_ops / 'native-selection.py'

    def test_absent_legacy_selection_uses_exact_canonical_stop_only_sibling(self):
        donor = self.missing_historical_selection()
        with m.locked(self.root): selection = m.binding(self.root, self.intent)
        pin = selection['pin']['helpers']['native-selection.py']
        self.assertEqual(pin['origin'], 'canonical-backend-sibling-stop-only')
        self.assertEqual(pin['path'], str(donor)); self.assertTrue(pin['selectedAbsent'])
        self.assertEqual(pin['selectedPath'], str(self.release / 'ops/native-selection.py'))
        self.assertEqual(pin['sha256'], m.sha(donor.read_bytes()))
        self.assertEqual(pin['stat'][:2], list(self.key(donor)))
        self.assertEqual(pin['backend']['path'], str(self.canonical_ops / 'host-clean-reset.py'))
        self.assertIn(str(donor.parent), pin['ancestry'])
        self.assertEqual(selection['modules']['native-selection.py'].__file__, str(donor))
        self.assertEqual(selection['modules']['install-journal.py'].__file__, str(self.release / 'ops/install-journal.py'))
        self.assertEqual(selection['pin']['selection']['bundle'], str(self.release))
        self.assertEqual(selection['pin']['selection']['receipt']['sha256'], self.intent)
        self.assertTrue(self.run_reset()['completeCleanReset'])
        self.assertTrue(donor.exists()); self.assertFalse((self.release / 'ops/native-selection.py').exists())

    def test_present_legacy_selection_never_silently_uses_donor(self):
        path = self.release / 'ops/native-selection.py'
        self.put(path, b'# synthetic unknown selected helper\n'); self.denied()
        self.assertTrue((self.canonical_ops / 'native-selection.py').exists())

    def test_present_unsafe_selection_never_silently_uses_donor(self):
        path = self.release / 'ops/native-selection.py'
        self.own(path, 1000); self.denied(); self.own(path, 0)
        held = path.with_name('held-selection.py'); path.rename(held)
        path.symlink_to(held); self.denied(); path.unlink()
        os.link(held, path); self.denied()
        self.assertTrue((self.canonical_ops / 'native-selection.py').exists())

    def test_missing_selected_ops_parent_is_not_leaf_absence_authority(self):
        self.missing_historical_selection()
        (self.release / 'ops').rename(self.release / 'held-ops')
        with self.assertRaises(FileNotFoundError): m.source_module(self.release, 'native-selection.py')

    def test_donor_foreign_operator_ownership_and_backend_ownership_refused(self):
        donor = self.missing_historical_selection()
        for uid in (999, 1000):
            with self.subTest(uid=uid):
                self.own(donor, uid); self.denied()
        self.own(donor, 0)
        self.own(self.canonical_ops / 'host-clean-reset.py', 1000); self.denied()

    def test_donor_symlink_hardlink_and_special_refused(self):
        donor = self.missing_historical_selection(); original = donor.read_bytes()
        held = donor.with_name('held-selection.py'); donor.rename(held)
        donor.symlink_to(held); self.denied(); donor.unlink()
        os.link(held, donor); self.denied(); donor.unlink()
        os.mkfifo(donor); self.denied(); donor.unlink()
        self.put(donor, original); donor.chmod(0o666); self.denied()

    def test_donor_symlink_ancestor_refused(self):
        self.missing_historical_selection(); held = self.canonical_ops.with_name('held-ops')
        self.canonical_ops.rename(held); self.canonical_ops.symlink_to(held)
        self.denied()

    def test_donor_missing_or_changed_bytes_refused(self):
        donor = self.missing_historical_selection(); body = donor.read_bytes()
        donor.unlink(); self.denied()
        self.put(donor, body + b'\n# synthetic unrecognized donor change\n'); self.denied()

    def test_selected_helper_appearing_during_donor_read_refused(self):
        donor = self.missing_historical_selection(); read = m.read_at; appeared = []
        def changed(fd, name, **kwargs):
            value = read(fd, name, **kwargs)
            if name == donor.name and self.key_fd(fd) == self.key(donor.parent) and not appeared:
                appeared.append(True)
                self.put(self.release / 'ops/native-selection.py', donor.read_bytes())
            return value
        with patch.object(m, 'read_at', side_effect=changed): self.denied()
        self.assertTrue(appeared)

    def test_donor_same_bytes_inode_swap_invalidates_reviewed_plan(self):
        donor = self.missing_historical_selection(); reviewed = self.review()
        original = self.key(donor); body = donor.read_bytes()
        donor.rename(donor.with_name('held-selection.py')); self.put(donor, body)
        self.assertNotEqual(original, self.key(donor))
        with self.assertRaises(m.Refusal): m.issue_stopped_lease(self.root, self.intent, reviewed['planSha256'])
        self.assertTrue((Path(self.rows[0]['graphRoot']) / 'overlay/layer/data').exists())

    def test_donor_swap_after_durable_intent_refuses_before_deletion(self):
        donor = self.missing_historical_selection(); write = m.write_evidence; changed = []
        def evidence(fd, name, value):
            write(fd, name, value)
            if name.endswith('-intent.json'):
                body = donor.read_bytes(); donor.rename(donor.with_name('held-selection.py'))
                self.put(donor, body); changed.append(True)
        with patch.object(m, 'write_evidence', side_effect=evidence):
            with self.assertRaises(m.Refusal): self.run_reset()
        self.assertTrue(changed)
        self.assertTrue((Path(self.rows[0]['graphRoot']) / 'overlay/layer/data').exists())
        result = json.loads(next((self.root / '.host-clean-reset').glob('*-result.json')).read_text())
        self.assertFalse(result['completeCleanReset'])

    def test_donor_ancestor_swap_during_selected_plan_refused(self):
        self.missing_historical_selection(); loaded = m.source_module; changed = []
        def module(release, name):
            result, pin = loaded(release, name)
            if name == 'native-selection.py':
                source_plan = result.source_plan
                def plan(*args, **kwargs):
                    value = source_plan(*args, **kwargs)
                    held = self.canonical_ops.with_name('held-ops'); self.canonical_ops.rename(held)
                    self.canonical_ops.mkdir(mode=0o755)
                    for filename in ('host-clean-reset.py', 'native-selection.py'):
                        self.put(self.canonical_ops / filename, (held / filename).read_bytes())
                    changed.append(True); return value
                result.source_plan = plan
            return result, pin
        with patch.object(m, 'source_module', side_effect=module): self.denied()
        self.assertTrue(changed)

    def test_historical_huly_named_graph_volume_and_broad_init_are_stop_only(self):
        self.ir['volumes']['huly-managed'] = {}  # Historical Podman-owned graph volume, no hostPath.
        self.ir['services']['huly'] = {'placement': 'rootless', 'rootlessDomain': 'apps', 'lifecycle': 'daemon',
                                      'image': 'sha256:' + 'a' * 64, 'volumes': ['huly-managed:/data']}
        self.ir['services']['volume-init'] = {'placement': 'rootful', 'lifecycle': 'oneshot', 'target': 'core',
                                            'image': 'sha256:' + 'a' * 64, 'volumes': [str(self.scope) + ':/legacy-scope']}
        row = next(row for row in self.rows if row['name'] == 'apps')
        row['services'] = ['huly']; row['persistentServices'] = ['huly']
        for scope, name, role, target, mount in (
                ('rootless-apps', 'huly', 'daemon', 'apps', 'huly-managed:/data'),
                ('rootful', 'volume-init', 'oneshot', 'core', str(self.scope) + ':/legacy-scope')):
            body = ('[Unit]\nPartOf=webservices-' + target + '.target\n[Container]\nContainerName=' + name +
                    '\nImage=sha256:' + 'a' * 64 + '\nVolume=' + mount + '\n[Service]\n')
            if role == 'oneshot': body += 'Type=oneshot\nRemainAfterExit=yes\nRestart=no\n'
            body += '[Install]\nWantedBy=webservices-' + target + '.target\n'
            self.put(self.release / 'quadlet' / scope / ('webservices-' + name + '.container'), body.encode())
        self.put(self.release / 'quadlet/rootful/webservices-core.target',
                 b'[Unit]\nPartOf=webservices.target\nWants=webservices-edge.service webservices-volume-init.service\n[Install]\nWantedBy=webservices.target\n')
        self.put(self.release / 'quadlet/rootless-apps/webservices-apps.target',
                 b'[Unit]\nPartOf=webservices.target\nWants=webservices-huly.service\n[Install]\nWantedBy=webservices.target\n')
        self.seal()
        # The NEW activation/role verifier is deliberately unavailable, never
        # relaxed or executed to obtain stop-only historical deletion custody.
        self.assertFalse((self.release / 'ops/verify-agent-vm-bundle.py').exists())
        result = self.run_reset(); self.assertTrue(result['completeCleanReset'])
        self.assertFalse(Path(row['graphRoot']).exists())

    def test_source_provenance_binding_is_required(self):
        path = self.release / 'stack.ir.json'; path.write_text('{}'); self.denied()

    def test_boolean_and_json_lease_cannot_authorize(self):
        reviewed = self.review()
        for lease in (True, {'stopped': True}, None, object()):
            with self.assertRaises(m.Refusal): m.execute(self.root, self.intent, reviewed['planSha256'], lease)
        with self.assertRaises(m.Refusal): m.StoppedLease(True, self.root, self.intent, reviewed['planSha256'])

    def test_lease_exact_plan_single_use_and_expiry(self):
        reviewed = self.review(); lease = m.issue_stopped_lease(self.root, self.intent, reviewed['planSha256'])
        with self.assertRaises(m.Refusal): m.execute(self.root, self.intent, 'a' * 64, lease)
        lease._until = 0
        with self.assertRaises(m.Refusal): m.execute(self.root, self.intent, reviewed['planSha256'], lease)
        lease = m.issue_stopped_lease(self.root, self.intent, reviewed['planSha256'])
        m.execute(self.root, self.intent, reviewed['planSha256'], lease)
        with self.assertRaises(m.Refusal): m.execute(self.root, self.intent, reviewed['planSha256'], lease)

    def test_plan_content_cas_drift_prevents_deletion(self):
        reviewed = self.review(); lease = m.issue_stopped_lease(self.root, self.intent, reviewed['planSha256'])
        self.put(Path(self.rows[0]['graphRoot']) / 'overlay/layer/data', b'synthetic changed')
        with self.assertRaises(m.Refusal): m.execute(self.root, self.intent, reviewed['planSha256'], lease)
        self.assertFalse((self.root / '.host-clean-reset').exists())

    def test_stopped_proof_failure_is_fail_closed(self):
        self.stop_failure = True; self.denied()

    def test_native_mount_alias_refused_before_deletion(self):
        dev = REAL_STAT(self.scope).st_dev
        base = f'1 0 {os.major(dev)}:{os.minor(dev)} / / rw - ext4 fixture rw'
        alias = f'2 1 {os.major(dev)}:{os.minor(dev)} {self.scope} /alias rw - ext4 fixture rw'
        with patch.object(m, 'mount_views', return_value=[[base], [base, alias]]): self.denied()

    def test_same_device_bind_mount_inside_scope_refused(self):
        dev = REAL_STAT(self.scope).st_dev
        base = f'1 0 {os.major(dev)}:{os.minor(dev)} / / rw - ext4 fixture rw'
        mounted = f'2 1 {os.major(dev)}:{os.minor(dev)} /other {self.scope}/graphs rw - ext4 fixture rw'
        with patch.object(m, 'mount_views', return_value=[[base, mounted], [base]]): self.denied()

    def test_existing_install_lock_is_not_replaced_or_created(self):
        lock = self.root / '.install.lock'; before = self.key(lock)
        self.review(); self.assertEqual(before, self.key(lock))
        lock.unlink()
        with self.assertRaises(FileNotFoundError): self.review()
        self.assertFalse(lock.exists())

    def test_real_flock_excludes_another_open_description(self):
        import fcntl
        fd = os.open(self.root / '.install.lock', os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError): self.review()
        finally: os.close(fd)

    def test_durable_intent_before_any_unlink(self):
        real_unlink = os.unlink; observed = []
        def unlink(*args, **kwargs):
            intents = list((self.root / '.host-clean-reset').glob('*-intent.json'))
            self.assertEqual(len(intents), 1)
            intent = json.loads(intents[0].read_text()); self.assertIn('plan', intent)
            self.assertFalse(intent['completeCleanReset']); observed.append(args[0])
            return real_unlink(*args, **kwargs)
        with patch.object(m.os, 'unlink', side_effect=unlink): result = self.run_reset()
        self.assertTrue(observed); self.assertTrue(result['completeCleanReset'])

    def test_failure_evidence_requires_new_review_even_if_no_content_deleted(self):
        reviewed = self.review(); lease = m.issue_stopped_lease(self.root, self.intent, reviewed['planSha256'])
        original = m.write_evidence
        def evidence(fd, name, value):
            original(fd, name, value)
            if name.endswith('-intent.json'): self.stop_failure = True
        with patch.object(m, 'write_evidence', side_effect=evidence):
            with self.assertRaises(m.Refusal): m.execute(self.root, self.intent, reviewed['planSha256'], lease)
        results = list((self.root / '.host-clean-reset').glob('*-result.json'))
        self.assertEqual(len(results), 1)
        result = json.loads(results[0].read_text()); self.assertFalse(result['completeCleanReset'])
        self.assertEqual(result['phase'], 'failed-partial-fresh-CAS-review-required')
        self.stop_failure = False
        fresh = self.review(); self.assertNotEqual(fresh['planSha256'], reviewed['planSha256'])
        with self.assertRaises(m.Refusal): m.issue_stopped_lease(self.root, self.intent, reviewed['planSha256'])
        self.run_reset(fresh)

    def test_legacy_private_2700_mask_zero_roots_deleted_not_repaired(self):
        legacy_access = sorted([[1, 7, m.UNDEFINED], [2, 7, 1000], [4, 7, m.UNDEFINED],
                                [16, 0, m.UNDEFINED], [32, 0, m.UNDEFINED]])
        legacy_default = sorted([[1, 7, m.UNDEFINED], [2, 7, 1000], [4, 7, m.UNDEFINED],
                                 [16, 7, m.UNDEFINED], [32, 0, m.UNDEFINED]])
        for row in self.rows:
            for key in m.ROOTS:
                path = Path(row[key]); path.chmod(0o2700)
                self.set_acl(path, legacy_access, legacy_default)
        before = copy.deepcopy(self.acls)
        reviewed = self.review(); self.assertEqual(before, self.acls)
        with patch.object(m.os, 'chmod', side_effect=AssertionError('Reset must not repair metadata')), \
             patch.object(m.os, 'fchmod', side_effect=AssertionError('Reset must not repair metadata')):
            result = self.run_reset(reviewed)
        self.assertTrue(result['completeCleanReset'])
        for row in self.rows:
            for key in m.ROOTS: self.assertFalse(Path(row[key]).exists())
        # Deleted legacy inode numbers may be reused by durable root evidence;
        # compare only retained ancestors, never stale model ownership/ACL keys.
        for path in (self.shared, self.scope, self.scope / 'volumes'):
            self.assertEqual(before[self.key(path)], self.acls[self.key(path)])

    def native_marker_acl(self):
        return sorted([[1, 6, m.UNDEFINED], [2, 7, 1000], [4, 7, m.UNDEFINED],
                       [16, 0, m.UNDEFINED], [32, 0, m.UNDEFINED]])

    def test_native_mixed_private_roots_and_masked_scope_marker_deleted_without_repair(self):
        legacy_access = sorted([[1, 7, m.UNDEFINED], [2, 7, 1000], [4, 7, m.UNDEFINED],
                                [16, 0, m.UNDEFINED], [32, 0, m.UNDEFINED]])
        legacy_default = sorted([[1, 7, m.UNDEFINED], [2, 7, 1000], [4, 7, m.UNDEFINED],
                                 [16, 7, m.UNDEFINED], [32, 0, m.UNDEFINED]])
        for row in self.rows:
            for key in m.ROOTS:
                path = Path(row[key]); path.chmod(0o2700)
                self.set_acl(path, legacy_access if key == 'stateRoot' else [],
                             legacy_default if key == 'stateRoot' else [])
        marker = self.scope / m.MARKER
        self.own(marker, 0, 1000); self.set_acl(marker, self.native_marker_acl())
        before = copy.deepcopy((self.acls, self.defaults)); marker_body = marker.read_bytes()
        reviewed = self.review(); self.assertEqual(before, (self.acls, self.defaults))
        with patch.object(m.os, 'chmod', side_effect=AssertionError('No profile repair')), \
             patch.object(m.os, 'fchmod', side_effect=AssertionError('No profile repair')), \
             patch.object(m.os, 'chown', side_effect=AssertionError('No ownership repair')), \
             patch.object(m.os, 'fchown', side_effect=AssertionError('No ownership repair')):
            result = self.run_reset(reviewed)
        self.assertTrue(result['completeCleanReset'])
        self.assertEqual(marker.read_bytes(), marker_body)
        self.assertEqual(self.owners[self.key(marker)], (0, 1000))
        self.assertEqual(self.acls[self.key(marker)], self.native_marker_acl())
        self.assertTrue(all(not Path(row[key]).exists() for row in self.rows for key in m.ROOTS))

    def test_native_private_sgid_profile_is_exact_owner_only_no_acl(self):
        path = Path(self.rows[0]['graphRoot']); actor = self.actors[0]
        fd = REAL_OPEN(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            path.chmod(0o2700); self.assertEqual(m.private_policy(fd, actor), m.custody(fd))
            for mode in (0o2701, 0o2710, 0o2770, 0o3700, 0o6700, 0o1700):
                with self.subTest(mode=mode):
                    path.chmod(mode)
                    with self.assertRaises(m.Refusal): m.private_policy(fd, actor)
            path.chmod(0o2700)
            for uid, gid in ((0, actor['gid']), (actor['uid'], 1000),
                             (self.actors[1]['uid'], self.actors[1]['gid'])):
                self.own(path, uid, gid)
                with self.subTest(uid=uid, gid=gid), self.assertRaises(m.Refusal): m.private_policy(fd, actor)
            self.own(path, actor['uid'], actor['gid'])
            for access, default in (([[2, 0, 999]], []), ([], [[1, 7, m.UNDEFINED]]),
                                    ([[1, 7, m.UNDEFINED]], [])):
                self.set_acl(path, access, default)
                with self.subTest(access=access, default=default), self.assertRaises(m.Refusal): m.private_policy(fd, actor)
        finally: os.close(fd)

    def test_native_scope_marker_all_finite_gid_acl_combinations(self):
        marker = self.scope / m.MARKER; fd = REAL_OPEN(self.scope, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for gid in (0, 1000):
                for access in ([], self.native_marker_acl()):
                    with self.subTest(gid=gid, access=access):
                        self.own(marker, 0, gid); self.set_acl(marker, access)
                        body, pin = m.read_at(fd, m.MARKER, private=True, scope_marker=True)
                        self.assertEqual(body, marker.read_bytes()); self.assertEqual(pin[3], gid)
                        self.assertEqual(self.acls[self.key(marker)], access)
        finally: os.close(fd)

    def test_native_scope_marker_foreign_or_effective_acl_and_default_refused(self):
        marker = self.scope / m.MARKER; fd = REAL_OPEN(self.scope, os.O_RDONLY | os.O_DIRECTORY)
        canonical = self.native_marker_acl()
        bad = ([row if row[0] != 16 else [16, 1, m.UNDEFINED] for row in canonical],
               canonical + [[2, 0, 999]], canonical + [[8, 7, 1000]],
               [row if row[0] != 2 else [2, 6, 1000] for row in canonical],
               [row if row[0] != 4 else [4, 0, m.UNDEFINED] for row in canonical],
               [row if row[0] != 32 else [32, 1, m.UNDEFINED] for row in canonical])
        try:
            self.own(marker, 0, 1000)
            for access, default in [(sorted(rows), []) for rows in bad] + [(canonical, canonical)]:
                self.set_acl(marker, access, default)
                with self.subTest(access=access, default=default), self.assertRaises(m.Refusal):
                    m.read_at(fd, m.MARKER, private=True, scope_marker=True)
            self.set_acl(marker, canonical)
            for uid, gid, mode in ((1000, 1000, 0o600), (0, 999, 0o600), (0, 1000, 0o620),
                                   (0, 1000, 0o640), (0, 1000, 0o2600)):
                self.own(marker, uid, gid); marker.chmod(mode)
                with self.subTest(uid=uid, gid=gid, mode=mode), self.assertRaises(m.Refusal):
                    m.read_at(fd, m.MARKER, private=True, scope_marker=True)
            self.own(marker, 0, 1000); marker.chmod(0o600)
            os.link(marker, self.scope / 'marker-hardlink')
            with self.assertRaises(m.Refusal): m.read_at(fd, m.MARKER, private=True, scope_marker=True)
        finally: os.close(fd)

    def test_native_marker_exception_cannot_apply_to_other_authority_or_parent(self):
        marker = self.scope / m.MARKER; self.own(marker, 0, 1000); self.set_acl(marker, self.native_marker_acl())
        fd = REAL_OPEN(self.scope, os.O_RDONLY | os.O_DIRECTORY)
        rootfd = REAL_OPEN(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            # Ordinary sealed reads still reject latent ACLs/GID1000.
            with self.assertRaises(m.Refusal): m.read_at(fd, m.MARKER, private=True, gid=0)
            for name in ('.install-intent.json', 'installation-receipt.json', 'bundle.json', '../' + m.MARKER):
                with self.subTest(name=name), self.assertRaises(m.Refusal):
                    m.read_at(fd, name, private=True, scope_marker=True)
            self.put(self.root / m.MARKER, marker.read_bytes(), 0o600)
            self.own(self.root / m.MARKER, 0, 1000); self.set_acl(self.root / m.MARKER, self.native_marker_acl())
            with self.assertRaises(m.Refusal): m.read_at(rootfd, m.MARKER, private=True, scope_marker=True)
        finally: os.close(fd); os.close(rootfd)

    def test_native_marker_read_acl_cas_change_refused(self):
        marker = self.scope / m.MARKER; self.own(marker, 0, 1000)
        fd = REAL_OPEN(self.scope, os.O_RDONLY | os.O_DIRECTORY); original = os.read
        try:
            for default in (False, True):
                self.set_acl(marker, self.native_marker_acl()); changed = []
                def read(child, count):
                    value = original(child, count)
                    if not changed:
                        changed.append(True)
                        self.set_acl(marker, self.native_marker_acl() if default else [],
                                     self.native_marker_acl() if default else [])
                    return value
                with self.subTest(default=default), patch.object(m.os, 'read', side_effect=read), self.assertRaises(m.Refusal):
                    m.read_at(fd, m.MARKER, private=True, scope_marker=True)
        finally: os.close(fd)

    def test_operator_defaults_without_named_group_and_other_none(self):
        for path in (self.shared, self.scope):
            self.acls[self.key(path)] = [row for row in self.acls[self.key(path)] if row != [8, 7, 1000]]
            self.defaults[self.key(path)] = [row for row in self.defaults[self.key(path)] if row != [8, 7, 1000]]
        before = copy.deepcopy((self.acls, self.defaults)); self.run_reset()
        self.assertEqual(before, (self.acls, self.defaults))

    def test_legacy_private_foreign_or_effective_operator_access_refused(self):
        path = Path(self.rows[0]['stateRoot']); path.chmod(0o2700)
        access = sorted([[1, 7, m.UNDEFINED], [2, 7, 1000], [4, 7, m.UNDEFINED],
                         [16, 0, m.UNDEFINED], [32, 0, m.UNDEFINED]])
        default = sorted([[1, 7, m.UNDEFINED], [2, 7, 1000], [4, 7, m.UNDEFINED],
                          [16, 7, m.UNDEFINED], [32, 0, m.UNDEFINED]])
        for changed in ([row if row[0] != 16 else [16, 7, m.UNDEFINED] for row in access],
                        access + [[2, 1, 999]]):
            self.set_acl(path, sorted(changed), default); self.denied()

    def test_absent_private_roots_recreate_after_review_refused(self):
        self.run_reset(); reviewed = self.review()
        lease = m.issue_stopped_lease(self.root, self.intent, reviewed['planSha256'])
        path = Path(self.rows[0]['stateRoot']); path.mkdir(mode=0o700); self.own(path, self.actors[0]['uid'])
        with self.assertRaises(m.Refusal): m.execute(self.root, self.intent, reviewed['planSha256'], lease)
        self.assertTrue(path.exists())

    def test_injected_partial_deletion_failure_preserves_evidence(self):
        original = m.erase
        def fail(*args, **kwargs):
            original(*args, **kwargs); raise OSError('synthetic injected failure after scope deletion')
        with patch.object(m, 'erase', side_effect=fail):
            with self.assertRaises(OSError): self.run_reset()
        result = json.loads(next((self.root / '.host-clean-reset').glob('*-result.json')).read_text())
        self.assertFalse(result['completeCleanReset']); self.assertTrue(self.operator_key.exists())
        self.assertEqual((self.root / '.install-intent.json').read_bytes(), self.original_intent)
        self.run_reset()

    def test_installed_exact_selected_sources_removed_no_prefix_sweep(self):
        root_target = self.physical(Path('/etc/systemd/system/webservices.target'))
        self.put(root_target, (self.release / 'quadlet/rootful/webservices.target').read_bytes())
        foreign = root_target.with_name('webservices-authored-unrelated.service'); self.put(foreign, b'synthetic authored')
        actor = self.actors[0]; conf = self.physical(Path(actor['home']) / '.config/containers/storage.conf')
        self.put(conf, ('[storage]\ndriver = "overlay"\ngraphroot = "' + self.rows[0]['graphRoot'] + '"\n').encode(), 0o600)
        self.own(conf, actor['uid'])
        self.run_reset(); self.assertFalse(conf.exists()); self.assertFalse(root_target.exists()); self.assertTrue(foreign.exists())

    def test_installed_updater_executable_cleared_only_on_exact_hash(self):
        updater = self.physical(Path('/usr/local/sbin/webservices-auto-update'))
        unrelated = updater.with_name('webservices-authored-unrelated'); self.put(unrelated, b'synthetic authored', 0o755)
        self.put(updater, b'synthetic foreign updater', 0o755); self.denied()
        self.assertTrue(updater.exists())
        self.put(updater, (self.release / 'ops/webservices-auto-update').read_bytes(), 0o755)
        result = self.run_reset(); self.assertTrue(result['completeCleanReset'])
        self.assertFalse(updater.exists()); self.assertTrue(unrelated.exists())

    def test_foreign_selected_installed_source_preserved_and_refused(self):
        path = self.physical(Path('/etc/systemd/system/webservices.target'))
        self.put(path, b'synthetic authored conflicting target'); self.denied(); self.assertTrue(path.exists())

    def test_linked_installed_source_refused(self):
        path = self.physical(Path('/etc/systemd/system/webservices.target')); path.symlink_to(self.outside / 'keep')
        self.denied()

    def test_unsealed_external_runtime_not_reported_complete(self):
        path = self.root / 'runtime-env'; path.mkdir(mode=0o700)
        self.put(path / 'synthetic.env', b'SYNTHETIC_FIXTURE_ONLY=1\n', 0o600); self.denied()
        self.assertTrue((path / 'synthetic.env').exists())

    def test_receipt_sealed_external_runtime_fingerprint_cleared(self):
        path = self.root / 'runtime-env'; path.mkdir(mode=0o700)
        self.put(path / 'synthetic.env', b'SYNTHETIC_FIXTURE_ONLY=1\n', 0o600)
        original = (self.root / '.install-intent.json').read_bytes()
        custody = m.review_runtime_custody(self.root, self.intent)
        self.assertEqual((self.root / '.install-intent.json').read_bytes(), original)
        self.receipt_extra['cleanResetCustody'] = custody['cleanResetCustody']
        self.seal(); self.run_reset(); self.assertEqual(list(path.iterdir()), [])

    def test_sealed_root_release_runtime_and_repo_cache_cleared_inputs_retained(self):
        runtime = self.release / 'runtime'; repos = self.release / 'repos'
        self.put(runtime / 'configs/synthetic-app.conf', b'synthetic rendered app configuration')
        self.put(repos / 'synthetic-build-cache/object', b'synthetic derived repository build cache')
        custody = m.review_runtime_custody(self.root, self.intent)
        self.receipt_extra['cleanResetCustody'] = custody['cleanResetCustody']; self.seal()
        result = self.run_reset()
        self.assertTrue(result['completeCleanReset'])
        self.assertEqual(list(runtime.iterdir()), []); self.assertEqual(list(repos.iterdir()), [])
        for name in m.CORE: self.assertTrue((self.release / name).is_file())

    def test_receipt_cannot_select_arbitrary_external_tree(self):
        self.receipt_extra['cleanResetCustody'] = {'externalTrees': {str(self.outside): 'a' * 64}}
        self.seal(); self.denied(); self.assertTrue((self.outside / 'keep').exists())

    def test_no_success_on_in_scope_repopulation(self):
        original = m.write_evidence
        def evidence(fd, name, value):
            original(fd, name, value)
            if '-progress-' in name and str(self.scope) in value.get('emptied', []):
                path = Path(self.rows[0]['graphRoot']); path.mkdir(mode=0o700)
                self.own(path, self.actors[0]['uid'])
                self.put(path / 'new-cache', b'synthetic race')
        with patch.object(m, 'write_evidence', side_effect=evidence):
            with self.assertRaises(m.Refusal): self.run_reset()
        result = json.loads(next((self.root / '.host-clean-reset').glob('*-result.json')).read_text())
        self.assertFalse(result['completeCleanReset'])

    def test_no_replace_claim_preserves_existing_destination(self):
        parent = Path(self.rows[0]['graphRoot'])
        source = parent / 'source'; destination = parent / 'occupied'
        self.put(source, b'synthetic source'); self.put(destination, b'synthetic collision')
        with m.directory(parent, m.binding(self.root, self.intent)['policies']) as fd:
            pin = m.fingerprint(m.os.stat(source.name, dir_fd=fd, follow_symlinks=False))
            with self.assertRaises(FileExistsError): m.claim(fd, source.name, destination.name, pin)
        self.assertEqual(source.read_bytes(), b'synthetic source')
        self.assertEqual(destination.read_bytes(), b'synthetic collision')

    def test_swapped_inode_is_claimed_but_never_deleted(self):
        original = m.claim; swapped = []
        def claim(parent, name, destination, expected):
            if not swapped and stat.S_ISREG(expected[4]):
                os.rename(name, 'held-original', src_dir_fd=parent, dst_dir_fd=parent)
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent)
                try: os.write(fd, b'synthetic substituted inode must not be deleted')
                finally: os.close(fd)
                swapped.append(destination)
            return original(parent, name, destination, expected)
        with patch.object(m, 'claim', side_effect=claim):
            with self.assertRaises(m.Refusal): self.run_reset()
        self.assertTrue(swapped)
        self.assertTrue(any(path.read_bytes() == b'synthetic substituted inode must not be deleted'
                            for path in self.scope.rglob(swapped[0])))
        self.assertTrue(list(self.scope.rglob('held-original')))
        result = json.loads(next((self.root / '.host-clean-reset').glob('*-result.json')).read_text())
        self.assertFalse(result['completeCleanReset']); self.assertIn('claimPrefix', result)

    def test_helper_change_after_durable_intent_prevents_first_deletion(self):
        original = m.write_evidence
        def evidence(fd, name, value):
            original(fd, name, value)
            if name.endswith('-intent.json'):
                helper = self.release / 'ops/install-journal.py'
                helper.write_bytes(helper.read_bytes() + b'\n# synthetic unrecognized change\n')
        with patch.object(m, 'write_evidence', side_effect=evidence):
            with self.assertRaises(m.Refusal): self.run_reset()
        self.assertTrue((Path(self.rows[0]['graphRoot']) / 'overlay/layer/data').exists())
        result = json.loads(next((self.root / '.host-clean-reset').glob('*-result.json')).read_text())
        self.assertFalse(result['completeCleanReset'])

    def test_selected_execute_acl_subset_is_pinned_without_broadening(self):
        for path in (self.shared, self.scope):
            self.acls[self.key(path)] = [row for row in self.acls[self.key(path)]
                                        if not (row[0] == 2 and row[2] == self.actors[0]['start'])]
        before = copy.deepcopy(self.acls); self.review(); self.assertEqual(before, self.acls)

    def test_evidence_no_replace(self):
        path = self.root / 'evidence'; path.mkdir(mode=0o700)
        with m.directory(path) as fd:
            m.write_evidence(fd, 'same', {'synthetic': 1})
            with self.assertRaises(FileExistsError): m.write_evidence(fd, 'same', {'synthetic': 2})
        self.assertEqual(json.loads((path / 'same').read_text()), {'synthetic': 1})

    def test_allocation_real_parser_uses_exact_uid_gid_tables(self):
        users = {actor['user']: types.SimpleNamespace(pw_uid=actor['uid'], pw_gid=actor['gid'],
                 pw_name=actor['user'], pw_dir=actor['home']) for actor in self.actors}
        bodies = {name: ''.join(f"{actor['user']}:{actor['start']}:65536\n" for actor in self.actors).encode()
                  for name in ('subuid', 'subgid')}
        def read(path, **kwargs): return bodies[path.name], [0] * 9
        with patch.object(m, 'read_file', side_effect=read), \
             patch.object(m.pwd, 'getpwnam', side_effect=lambda user: users[user]), \
             patch.object(m.pwd, 'getpwuid', side_effect=lambda uid: types.SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name='operator')
                          if uid == 1000 else next(user for user in users.values() if user.pw_uid == uid)), \
             patch.object(m.pwd, 'getpwall', return_value=list(users.values())), \
             patch.object(m.grp, 'getgrall', return_value=[types.SimpleNamespace(gr_gid=actor['gid']) for actor in self.actors]), \
             patch.object(m.grp, 'getgrgid', side_effect=lambda gid: types.SimpleNamespace(gr_name=next(
                 actor['user'] for actor in self.actors if actor['gid'] == gid), gr_mem=[])):
            result = REAL_ALLOCATION(self.rows); self.assertEqual(len(result['actors']), 7)
            bodies['subgid'] = bodies['subgid'].replace(b'2000000:', b'2000001:', 1)
            with self.assertRaises(m.Refusal): REAL_ALLOCATION(self.rows)
            bodies['subgid'] = bodies['subuid'] + b'foreign:2000010:65536\n'
            with self.assertRaises(m.Refusal): REAL_ALLOCATION(self.rows)

    def test_actual_canonical_offline_gate_against_model_process_linger_and_triggers(self, legacy=False):
        with m.locked(self.root): selection = m.binding(self.root, self.intent)
        m.external_plan(selection)
        if legacy:
            for name in ('install-journal.py', 'grant-rootless-volume-parent-traverse.py'):
                selection['modules'][name] = m.legacy_stop_module(name)
        journal = selection['modules']['install-journal.py']
        storage = selection['modules']['grant-rootless-volume-parent-traverse.py']
        processes = self.base / 'model-proc'; (processes / '1').mkdir(parents=True)
        status = processes / '1/status'; status.write_text('Uid:\t0 0 0 0\nGid:\t0 0 0 0\nGroups:\t0\n')
        linger = self.base / 'model-linger'; linger.mkdir()
        bad = {'trigger': False, 'manager': False}
        def path(value):
            if str(value) == '/proc': return processes
            if str(value) == '/var/lib/systemd/linger': return linger
            return Path(value)
        def native(command, **kwargs):
            if 'is-enabled' in command:
                self.assertIn('SYSTEMD_OFFLINE=1', command)
                state = 'enabled' if bad['trigger'] else 'disabled'
                return types.SimpleNamespace(returncode=1, stdout=(state + '\n') * len(command[command.index('is-enabled') + 1:]))
            if 'list-jobs' in command: return types.SimpleNamespace(returncode=0, stdout='')
            unit = command[command.index('show') + 1]
            if unit.startswith('user@'):
                self.assertNotIn('--user', command)
                values = {'Id': unit, 'LoadState': 'loaded', 'ActiveState': 'active' if bad['manager'] else 'inactive',
                          'SubState': 'running' if bad['manager'] else 'dead', 'MainPID': '0', 'Job': ''}
            else:
                values = {'Id': unit, 'LoadState': 'not-found', 'ActiveState': 'inactive', 'SubState': 'dead',
                          'MainPID': '0', 'Job': '', 'UnitFileState': 'not-found', 'Triggers': '', 'TriggeredBy': '',
                          'Transient': 'no', 'DropInPaths': '', 'Names': unit, 'FragmentPath': '', 'SourcePath': ''}
            return types.SimpleNamespace(returncode=0, stdout='\n'.join(key + '=' + value for key, value in values.items()))
        with patch.object(journal, 'Path', side_effect=path), \
             patch.object(storage, 'namespace_root_id', side_effect=lambda user: next(
                 actor['start'] for actor in self.actors if actor['user'] == user)), \
             patch.object(journal.subprocess, 'run', side_effect=native), \
             patch.object(m, 'run_read', side_effect=native), \
             patch.object(m, 'process_statuses', side_effect=lambda: [status.read_text()]):
            REAL_STOPPED(selection)
            for key in ('trigger', 'manager'):
                bad[key] = True
                with self.assertRaises((m.Refusal, ValueError)): REAL_STOPPED(selection)
                bad[key] = False
            (linger / self.actors[0]['user']).touch()
            with self.assertRaises(ValueError): REAL_STOPPED(selection)
            (linger / self.actors[0]['user']).unlink()
            status.write_text(f"Uid:\t{self.actors[0]['start']} 0 0 0\nGid:\t0 0 0 0\nGroups:\t0\n")
            with self.assertRaises(ValueError): REAL_STOPPED(selection)
            status.write_text(f"Uid:\t0 0 0 0\nGid:\t0 0 0 0\nGroups:\t{self.actors[0]['start']}\n")
            with self.assertRaises(m.Refusal): REAL_STOPPED(selection)

    def test_reviewed_legacy_source_never_executes_old_top_level_or_mutators(self):
        cases = [('install-journal.py', 'ae4694efcb00999d42297cd5f79905925b09e65cf930c5ebddb38bd27f3403e8',
                  {'offline_actor', 'offline_control', 'verify_offline_actor'}),
                 ('grant-rootless-volume-parent-traverse.py', '0dcf715f2581a783702128d2fc12ff390fe21de45868bc4347dc809d08a74a32',
                  {'namespace_root_id'})]
        # Digest is explicitly a MODEL here; actual old-byte SHA/source fixtures
        # are separately qualified, never accepted from this sentinel at runtime.
        for name, digest, functions in cases:
            with self.subTest(name=name), patch.object(m, 'helper_bytes', return_value=(
                    b'raise AssertionError("old top-level must not run")', {'path': '/never-execute-old', 'sha256': digest})), \
                 patch.object(m, 'sha', return_value=digest):
                module, pin = m.source_module(self.release, name)
                self.assertTrue(pin['stopOnlyAdapter']); self.assertEqual(pin['sha256'], digest)
                self.assertEqual({key for key, value in vars(module).items() if isinstance(value, types.FunctionType)}, functions)
                for denied in ('write', 'update', 'main', 'grant', 'prepare_scope', 'exact_execute', 'standalone_binding'):
                    self.assertFalse(hasattr(module, denied))
        with patch.object(m, 'helper_bytes', return_value=(b'unknown old module', {'path': '/never-execute'})):
            with self.assertRaises(m.Refusal): m.source_module(self.release, 'install-journal.py')

    def test_legacy_stop_only_closure_preserves_actual_offline_negative_gates(self):
        self.test_actual_canonical_offline_gate_against_model_process_linger_and_triggers(legacy=True)

    def test_dev16_legacy_installer_requires_original_publication_stage(self):
        digest = '7d7f7b8758ab5320ea8d7614fe5be5493c717ff28e9d0f10a88afdf7078b3bf2'
        for steps in (None, [], ['preparing'], ['preparing', 'failed', 'retired-failed'],
                      ['units-selected'], ['preparing', 'failed', 'units-selected']):
            with self.subTest(steps=steps): self.assertFalse(m.legacy_installer_published(digest, {'steps': steps}))
        self.assertTrue(m.legacy_installer_published(digest, {'steps': ['preparing', 'units-selected', 'building', 'failed', 'retired-failed']}))
        self.assertFalse(m.legacy_installer_published('0' * 64, {'steps': ['preparing', 'units-selected']}))

    def test_legacy_subordinate_reader_is_read_only_and_exact(self):
        helper = m.legacy_stop_module('grant-rootless-volume-parent-traverse.py')
        files = [self.base / name for name in ('model-subuid', 'model-subgid')]
        user = self.actors[0]['user']
        def emit(uid, gid):
            self.put(files[0], uid.encode()); self.put(files[1], gid.encode())
        body = user + ':2000000:65536\n'; emit(body, body)
        with patch.object(helper.pwd, 'getpwall', return_value=[]), patch.object(helper.grp, 'getgrall', return_value=[]):
            self.assertEqual(helper.namespace_root_id(user, files=files), 2000000)
            for uid, gid in ((body, user + ':2000001:65536\n'),
                             (body + 'foreign:2000001:65536\n', body),
                             (user + ':2000000:10\n', body), (body + body, body), ('bad\n', body)):
                emit(uid, gid)
                with self.subTest(uid=uid, gid=gid), self.assertRaises(ValueError): helper.namespace_root_id(user, files=files)
            emit(body, body); self.own(files[0], 1000, 1000)
            with self.assertRaises(ValueError): helper.namespace_root_id(user, files=files)

    def test_real_stopped_adapter_calls_verified_canonical_offline_functions_only(self):
        with m.locked(self.root): selection = m.binding(self.root, self.intent)
        m.external_plan(selection)
        journal = selection['modules']['install-journal.py']; called = []; enabled_updater = [False]
        def offline(release, label):
            called.append(label); return next(row for row in self.rows if label == 'rootless-' + row['name'])
        def verify(row, command): self.assertEqual(command[-2:], ['/usr/bin/systemctl', '--user'])
        def native(command):
            if '--user' in command:
                self.assertIn('SYSTEMD_OFFLINE=1', command)
                self.assertIn('is-enabled', command)
                return types.SimpleNamespace(returncode=1, stdout='disabled\n' * len(command[command.index('is-enabled') + 1:]))
            if 'list-jobs' in command: return types.SimpleNamespace(returncode=0, stdout='')
            self.assertIn('show', command); unit = command[command.index('show') + 1]
            values = {'Id': unit, 'LoadState': 'not-found', 'ActiveState': 'inactive', 'SubState': 'dead',
                      'MainPID': '0', 'Job': '', 'UnitFileState': 'not-found', 'Triggers': '', 'TriggeredBy': '',
                      'Transient': 'no', 'DropInPaths': '', 'Names': unit, 'FragmentPath': '', 'SourcePath': ''}
            if enabled_updater[0] and unit == 'webservices-auto-update.timer':
                values.update(LoadState='loaded', UnitFileState='enabled', FragmentPath='/etc/systemd/system/webservices-auto-update.timer')
            return types.SimpleNamespace(returncode=0, stdout='\n'.join(key + '=' + value for key, value in values.items()))
        with patch.object(journal, 'offline_actor', side_effect=offline), \
             patch.object(journal, 'verify_offline_actor', side_effect=verify), \
             patch.object(m, 'process_statuses', return_value=['Uid:\t0 0 0 0\nGid:\t0 0 0 0\nGroups:\t0\n']), \
             patch.object(m, 'run_read', side_effect=native):
            REAL_STOPPED(selection); self.assertEqual(len(called), 7)
            enabled_updater[0] = True
            with self.assertRaises(m.Refusal): REAL_STOPPED(selection)
            enabled_updater[0] = False
            for uid, gid in ((self.actors[0]['uid'], 0), (0, self.actors[0]['start'] + 1)):
                with patch.object(m, 'process_statuses', return_value=[f'Uid:\t{uid} 0 0 0\nGid:\t{gid} 0 0 0\nGroups:\t0\n']):
                    with self.assertRaises(m.Refusal): REAL_STOPPED(selection)
            with patch.object(journal, 'offline_actor', return_value=None):
                with self.assertRaises(m.Refusal): REAL_STOPPED(selection)


    @contextlib.contextmanager
    def root_control_profile(self):
        with m.locked(self.root): selection = m.binding(self.root, self.intent)
        m.external_plan(selection)
        units = set(selection['pin']['selection']['scopes']['rootful']['units']) | {
            'webservices-auto-update.timer', 'webservices-auto-update.service', 'webservices-runtime-env.service'}
        values = {}
        for unit in units:
            row = {'Id': unit, 'LoadState': 'not-found', 'ActiveState': 'inactive', 'SubState': 'dead',
                   'MainPID': '0', 'Job': '', 'UnitFileState': 'not-found', 'Triggers': '', 'TriggeredBy': '',
                   'Transient': 'no', 'DropInPaths': '', 'Names': unit, 'FragmentPath': '', 'SourcePath': ''}
            if unit.endswith(('.target', '.timer')):
                row.update(LoadState='loaded', UnitFileState='disabled', FragmentPath='/etc/systemd/system/' + unit)
                row.pop('MainPID')
            if unit == 'webservices-edge.service':
                row.update(LoadState='loaded', UnitFileState='generated',
                           SourcePath='/etc/containers/systemd/webservices-edge.container',
                           FragmentPath='/run/systemd/generator/' + unit)
            values[unit] = row
        journal = selection['modules']['install-journal.py']
        def native(command):
            if '--user' in command:
                self.assertIn('SYSTEMD_OFFLINE=1', command); self.assertIn('is-enabled', command)
                return types.SimpleNamespace(returncode=1, stdout='disabled\n' * len(command[command.index('is-enabled') + 1:]))
            if 'list-jobs' in command: return types.SimpleNamespace(returncode=0, stdout='')
            self.assertIn('show', command); unit = command[command.index('show') + 1]
            return types.SimpleNamespace(returncode=0, stdout='\n'.join(k + '=' + v for k, v in values[unit].items()))
        with patch.object(journal, 'offline_actor', side_effect=lambda release, label: next(
                row for row in self.rows if label == 'rootless-' + row['name'])), \
             patch.object(journal, 'verify_offline_actor', return_value=None), \
             patch.object(m, 'process_statuses', return_value=['Uid:\t0 0 0 0\nGid:\t0 0 0 0\nGroups:\t0\n']), \
             patch.object(m, 'run_read', side_effect=native):
            yield selection, values

    def test_generated_selected_service_and_honest_nonservice_pid_absence(self):
        with self.root_control_profile() as (selection, values):
            REAL_STOPPED(selection)
            self.assertNotIn('MainPID', values['webservices-auto-update.timer'])
            self.assertEqual(values['webservices-edge.service']['UnitFileState'], 'generated')
            values['webservices-edge.service'].update(ActiveState='failed', SubState='failed')
            REAL_STOPPED(selection)

    def test_generated_service_requires_both_exact_selected_source_and_generator_fragment(self):
        with self.root_control_profile() as (selection, values):
            row = values['webservices-edge.service']; original = dict(row)
            for change in ({'SourcePath': '/etc/containers/systemd/foreign.container'},
                           {'SourcePath': ''}, {'FragmentPath': '/tmp/forged.service'},
                           {'FragmentPath': '/run/systemd/generator.late/webservices-edge.service'},
                           {'FragmentPath': '/run/systemd/generator/foreign.service'},
                           {'Names': ''}, {'Names': row['Id'] + ' alias.service'},
                           {'LoadState': 'not-found'}, {'DropInPaths': '/etc/systemd/system/foreign.conf'}):
                row.clear(); row.update(original); row.update(change)
                with self.subTest(change=change), self.assertRaises(m.Refusal): REAL_STOPPED(selection)

    def test_service_pid_and_all_other_requested_fields_remain_mandatory(self):
        with self.root_control_profile() as (selection, values):
            for unit, field in (('webservices-edge.service', 'MainPID'),
                                ('webservices-edge.service', 'Job'), ('webservices-apps.target', 'Job'),
                                ('webservices-auto-update.timer', 'SourcePath')):
                saved = values[unit].pop(field)
                with self.subTest(unit=unit, field=field), self.assertRaises(m.Refusal): REAL_STOPPED(selection)
                values[unit][field] = saved
            values['webservices-edge.service']['UnknownProperty'] = 'no'
            with self.assertRaises(m.Refusal): REAL_STOPPED(selection)

    def test_nonservice_pid_omission_does_not_allow_present_bad_pid(self):
        with self.root_control_profile() as (selection, values):
            row = values['webservices-auto-update.timer']
            for pid in ('', '1', 'unknown'):
                row['MainPID'] = pid
                with self.subTest(pid=pid), self.assertRaises(m.Refusal): REAL_STOPPED(selection)
            row['MainPID'] = '0'; REAL_STOPPED(selection)
            row.pop('MainPID'); REAL_STOPPED(selection)
            unit = 'webservices-test.socket'
            selection['pin']['selection']['scopes']['rootful']['units'].append(unit)
            values[unit] = dict(row, Id=unit, Names=unit, LoadState='not-found', UnitFileState='not-found', FragmentPath='')
            REAL_STOPPED(selection)
            values[unit]['UnitFileState'] = 'static'
            with self.assertRaises(m.Refusal): REAL_STOPPED(selection)

    def test_generated_profile_never_waives_active_exited_pid_jobs_or_foreign_triggers(self):
        with self.root_control_profile() as (selection, values):
            row = values['webservices-edge.service']; original = dict(row)
            for change in ({'ActiveState': 'active', 'SubState': 'exited'}, {'MainPID': '99'},
                           {'Job': '12'}, {'Triggers': 'foreign.service'}, {'TriggeredBy': 'foreign.timer'},
                           {'Transient': 'yes'}):
                row.clear(); row.update(original); row.update(change)
                with self.subTest(change=change), self.assertRaises(m.Refusal): REAL_STOPPED(selection)
            row.clear(); row.update(original)
            values['webservices-runtime-env.service'].update(LoadState='loaded', UnitFileState='static',
                FragmentPath='/etc/systemd/system/webservices-runtime-env.service', ActiveState='active', SubState='exited')
            with self.assertRaises(m.Refusal): REAL_STOPPED(selection)

    def test_loaded_target_timer_activation_policy_not_relaxed_by_pid_absence(self):
        with self.root_control_profile() as (selection, values):
            for unit in ('webservices-apps.target', 'webservices-auto-update.timer'):
                row = values[unit]
                for state in ('enabled', 'static', 'generated'):
                    row['UnitFileState'] = state
                    with self.subTest(unit=unit, state=state), self.assertRaises(m.Refusal): REAL_STOPPED(selection)
                row['UnitFileState'] = 'disabled'
            REAL_STOPPED(selection)

    @contextlib.contextmanager
    def network_stop_api_model(self, units=('webservices-caddy-network.service',)):
        # API-only model; owning source/native-control proof is separate.
        plan = {'units': {unit: '/etc/containers/systemd/' + unit.removesuffix('-network.service') + '.network' for unit in units},
                'controls': {unit: {'ActiveState': 'active', 'SubState': 'exited'} for unit in units},
                'authority': self.intent}
        selection = {'actors': dict.fromkeys(m.IDENTITIES)}
        def snapshot(root, intent, pin): return m.strict(m.canonical(plan)), selection
        def dispatch(unit): plan['controls'][unit].update(ActiveState='inactive', SubState='dead')
        with patch.object(m, '_network_stop_snapshot', side_effect=snapshot) as snapshots, \
             patch.object(m, '_dispatch_network_stop', side_effect=dispatch) as stops:
            yield plan, snapshots, stops

    def test_network_stop_requires_exact_typed_live_single_use_authority(self):
        with self.network_stop_api_model() as (plan, snapshots, stops):
            for fake in (True, {}, object()):
                with self.assertRaises(m.Refusal): m.execute_network_stop(self.root, self.intent, '0' * 64, fake)
            with self.assertRaises(m.Refusal): m.NetworkStopLease(object(), self.root, self.intent, plan)
            prepared = m.prepare_network_stop(self.root, self.intent); lease = prepared['lease']; digest = prepared['planSha256']
            with self.assertRaises(m.Refusal): m.execute_network_stop(self.root, self.intent, '0' * 64, lease)
            result = m.execute_network_stop(self.root, self.intent, digest, lease)
            self.assertTrue(result['completed']); self.assertFalse(result['resetAuthorized'])
            self.assertFalse(result['deletionAuthorized']); self.assertFalse(result['activationAuthorized'])
            self.assertEqual(result['stoppedUnits'], ['webservices-caddy-network.service'])
            self.assertEqual(snapshots.call_count, 4); self.assertEqual(stops.call_count, 1)
            with self.assertRaises(m.Refusal): m.execute_network_stop(self.root, self.intent, digest, lease)
            self.assertEqual(stops.call_count, 1)

    def test_network_stop_rejects_expired_foreign_process_and_tampered_lease(self):
        with self.network_stop_api_model() as (_, snapshots, stops):
            for change in ('expired', 'foreign-pid', 'modified-plan'):
                prepared = m.prepare_network_stop(self.root, self.intent); lease = prepared['lease']
                if change == 'expired': lease._until = 0
                elif change == 'foreign-pid': lease._pid += 1
                else: lease._plan['authority'] = 'tampered'
                with self.subTest(change=change), self.assertRaises(m.Refusal):
                    m.execute_network_stop(self.root, self.intent, prepared['planSha256'], lease)
            stops.assert_not_called()

    def test_network_stop_rechecks_original_source_before_each_dispatch_and_never_continues_after_cas_failure(self):
        units = ('webservices-caddy-network.service', 'webservices-internet-network.service')
        with self.network_stop_api_model(units) as (plan, snapshots, stops):
            prepared = m.prepare_network_stop(self.root, self.intent)
            def first_only(unit):
                plan['controls'][unit].update(ActiveState='inactive', SubState='dead')
                plan['authority'] = 'changed original source'
            stops.side_effect = first_only
            with self.assertRaises(m.Refusal):
                m.execute_network_stop(self.root, self.intent, prepared['planSha256'], prepared['lease'])
            self.assertEqual(stops.call_args_list, [unittest.mock.call(units[0])])
            self.assertEqual(plan['controls'][units[1]]['ActiveState'], 'active')
            self.assertTrue(prepared['lease']._used)
        with self.network_stop_api_model() as (plan, snapshots, stops):
            prepared = m.prepare_network_stop(self.root, self.intent); plan['authority'] = 'changed before dispatch'
            with self.assertRaises(m.Refusal):
                m.execute_network_stop(self.root, self.intent, prepared['planSha256'], prepared['lease'])
            stops.assert_not_called()

    def test_network_stop_dispatch_is_one_exact_rootful_native_stop_without_force_or_fallback(self):
        with patch.object(m.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0)) as dispatch:
            m._dispatch_network_stop('webservices-caddy-network.service')
            self.assertEqual(dispatch.call_args.args[0], ['/usr/bin/systemctl', 'stop', '--', 'webservices-caddy-network.service'])
            self.assertEqual(dispatch.call_args.kwargs['timeout'], 30)
            self.assertEqual(dispatch.call_args.kwargs['env'], {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
            for foreign in ('webservices.target', 'webservices-edge.service', 'webservices-auto-update.timer',
                            'webservices-other-network.service', '--user', 'webservices-caddy.network'):
                with self.subTest(unit=foreign), self.assertRaises(m.Refusal): m._dispatch_network_stop(foreign)
            self.assertEqual(dispatch.call_count, 1)
            dispatch.return_value.returncode = 1
            with self.assertRaises(m.Refusal): m._dispatch_network_stop('webservices-caddy-network.service')
            self.assertEqual(dispatch.call_count, 2)
            dispatch.side_effect = subprocess.TimeoutExpired('systemctl', 30)
            with self.assertRaises(m.Refusal): m._dispatch_network_stop('webservices-caddy-network.service')
            self.assertEqual(dispatch.call_count, 3)

    def original_fixture_selection(self):
        # MODEL already-verified original source/public-version frame, not actual
        # original IR bytes or an installed custody proof. Real temp FD/inodes.
        selection = m.binding(self.root, self.intent)
        selection['pin'] = copy.deepcopy(selection['pin']); selection['receipt'] = copy.deepcopy(selection['receipt'])
        selection['ir'] = copy.deepcopy(selection['ir'])
        selection['receipt']['steps'] = ['preparing', 'units-selected', 'failed', 'retired-failed']
        selection['pin']['helpers']['install-podman-bundle.sh']['sha256'] = '7d7f7b8758ab5320ea8d7614fe5be5493c717ff28e9d0f10a88afdf7078b3bf2'
        selection['pin']['helpers']['grant-rootless-volume-parent-traverse.py']['sha256'] = '0dcf715f2581a783702128d2fc12ff390fe21de45868bc4347dc809d08a74a32'
        media = self.scope / 'fixtures/media'
        volumes = {'jellyfin_media': {'hostPath': str(media / 'jellyfin-media'), 'rootlessStrategy': 'shared'},
                   'qbittorrent_data': {'hostPath': str(media / 'qbittorrent'), 'rootlessStrategy': 'shared'},
                   'seafile_files': {'hostPath': str(media / 'seafile-media'), 'rootlessStrategy': 'copy'}}
        selection['ir']['volumes'].update(volumes)
        for name, mount in [('jellyfin', 'jellyfin_media:/media:ro'), ('qbittorrent', 'qbittorrent_data:/downloads'), ('seafile', 'seafile_files:/shared')]:
            selection['ir']['services'][name] = {'module': name, 'placement': 'rootless', 'rootlessDomain': 'apps', 'volumes': [mount]}
        selection['ir']['services']['volume-init'] = {'module': 'stack-foundation', 'placement': 'rootful',
            'volumes': [value['hostPath'] + ':' + value['hostPath'] + ':rw' for value in volumes.values()]}
        profiles = m.original_fixture_profiles(selection); self.assertEqual(len(profiles), 5)
        for name, profile in profiles.items():
            path = Path(name); path.mkdir(parents=True, exist_ok=True); path.chmod(profile['mode'])
            self.own(path, profile['uid'], profile['gid']); self.set_acl(path, profile['acl'], profile['defaultAcl'])
        return selection

    def scan_original_fixture(self, selection):
        retained = set(selection['policies']) - {m.SHARED, m.SCOPE} - set(selection['roots'])
        with m.directory(self.scope, selection['policies']) as fd: return m.scan(fd, selection, retain=retained)

    def test_original_fixture_exact_source_contract_and_empty_numeric_profiles_pass(self):
        selection = self.original_fixture_selection(); profiles = m.original_fixture_profiles(selection)
        before = {name: m.fingerprint(m.os.stat(name)) for name in profiles}
        nodes = self.scan_original_fixture(selection)
        fixtures = [node for node in nodes if str(self.scope / node['path']) in profiles]
        self.assertEqual(len(fixtures), 5)
        self.assertTrue(all(node['kind'] == 'directory' and node['domain'] is None and node['retain'] is False for node in fixtures))
        self.assertEqual(before, {name: m.fingerprint(m.os.stat(name)) for name in profiles})
        self.assertFalse(self.cold_calls)  # no native engine, mutator, repair or directory adoption

    def test_original_fixture_empty_directory_erase_is_not_retained_infrastructure(self):
        selection = self.original_fixture_selection(); nodes = self.scan_original_fixture(selection)
        with m.directory(self.scope, selection['policies']) as fd:
            expected = [m.MARKER, *[Path(node['path']).name for node in nodes if Path(node['path']).parent == Path('.')]]
            m.erase(fd, nodes, expected_names=expected)
        self.assertFalse((self.scope / 'fixtures').exists())
        self.assertTrue(all(node['kind'] == 'directory' and node['retain'] for node in self.scan_original_fixture(selection)))
        self.assertTrue((self.scope / m.MARKER).exists()); self.assertTrue((self.outside / 'keep').exists())

    def test_original_fixture_unpublished_unknown_helpers_inputs_phase_or_actor_never_qualify(self):
        selection = self.original_fixture_selection(); profiles = m.original_fixture_profiles(selection)
        def copied(): return dict(selection, pin=copy.deepcopy(selection['pin']), receipt=copy.deepcopy(selection['receipt']),
                                  actors=copy.deepcopy(selection['actors']), ir=copy.deepcopy(selection['ir']))
        variants = []
        for name in ('install-podman-bundle.sh', 'grant-rootless-volume-parent-traverse.py'):
            bad = copied(); bad['pin']['helpers'][name]['sha256'] = 'f' * 64; variants.append(bad)
        bad = copied(); bad['receipt']['steps'] = ['preparing', 'failed']; variants.append(bad)
        bad = copied(); bad['receipt']['phase'] = 'active'; variants.append(bad)
        bad = copied(); bad['pin']['sourceInputs']['stack.ir.json']['sha256'] = 'e' * 64; variants.append(bad)
        for field in ('uid', 'gid'):
            bad = copied(); bad['actors']['apps'][field] = 782; variants.append(bad)
        for index, bad in enumerate(variants):
            # An output-shaped JSON dictionary can never confer permissions.
            bad['pin']['originalFixtureProfiles'] = profiles
            with self.subTest(index=index):
                self.assertEqual(m.original_fixture_profiles(bad), {})
                with self.assertRaises(m.Refusal): self.scan_original_fixture(bad)

    def test_original_fixture_any_changed_declaration_or_consumer_stays_foreign(self):
        selection = self.original_fixture_selection()
        variants = []
        for change in ({'rootlessStrategy': 'copy'}, {'rootlessAccess': 'read-only'}, {'extra': 'not reviewed'}, {'hostPath': str(self.scope / 'other')}):
            ir = copy.deepcopy(selection['ir']); ir['volumes']['jellyfin_media'].update(change); variants.append(ir)
        ir = copy.deepcopy(selection['ir']); ir['volumes']['extra'] = {'hostPath': str(self.scope / 'fixtures/media/extra')}; variants.append(ir)
        for change in ({'rootlessDomain': 'platform'}, {'module': 'foreign'}, {'volumes': ['jellyfin_media:/media:rw']}):
            ir = copy.deepcopy(selection['ir']); ir['services']['jellyfin'].update(change); variants.append(ir)
        ir = copy.deepcopy(selection['ir']); ir['services'].pop('volume-init'); variants.append(ir)
        for index, ir in enumerate(variants):
            bad = dict(selection, ir=ir)
            with self.subTest(index=index):
                self.assertEqual(m.original_fixture_profiles(bad), {})
                with self.assertRaises(m.Refusal): self.scan_original_fixture(bad)

    def test_original_fixture_uid_gid_mode_access_and_default_acl_exact_not_cleared(self):
        selection = self.original_fixture_selection(); path = self.scope / 'fixtures'
        profile = m.original_fixture_profiles(selection)[str(path)]
        for uid, gid, mode in [(1, 1000, 0o2750), (0, 1001, 0o2750), (0, 0, 0o2750), (0, 1000, 0o2770), (0, 1000, 0o750)]:
            self.own(path, uid, gid); path.chmod(mode)
            with self.subTest(uid=uid, gid=gid, mode=mode), self.assertRaises(m.Refusal): self.scan_original_fixture(selection)
        self.own(path, 0, 1000); path.chmod(profile['mode'])
        for access, default in [(profile['acl'] + [[2, 7, 1001]], profile['defaultAcl']),
                                (profile['acl'], profile['defaultAcl'] + [[2, 7, 782]]), ([], []),
                                (profile['acl'], [])]:
            self.set_acl(path, access, default)
            with self.subTest(access=access, default=default), self.assertRaises(m.Refusal): self.scan_original_fixture(selection)
            self.assertEqual(self.acls[self.key(path)], access); self.assertEqual(self.defaults[self.key(path)], default)

    def test_original_fixture_nonempty_or_undeclared_child_refuses_before_body_read(self):
        selection = self.original_fixture_selection(); path = self.scope / 'fixtures/media/jellyfin-media/unproven'
        self.put(path, b'NEVER READ THIS SYNTHETIC BODY'); original = m.os.open
        def no_body(name, *args, **kwargs):
            self.assertNotEqual(str(name), 'unproven'); return original(name, *args, **kwargs)
        with patch.object(m.os, 'open', side_effect=no_body), self.assertRaises(m.Refusal): self.scan_original_fixture(selection)
        self.assertEqual(path.read_bytes(), b'NEVER READ THIS SYNTHETIC BODY'); path.unlink()
        child = self.scope / 'fixtures/undeclared'; child.mkdir(); self.own(child, 0, 1000)
        with self.assertRaises(m.Refusal): self.scan_original_fixture(selection)
        self.assertTrue(child.exists())

    def test_original_fixture_symlink_and_original_inode_replacement_refuse(self):
        selection = self.original_fixture_selection(); path = self.scope / 'fixtures/media/seafile-media'
        retained = self.outside / 'retained-source-leaf'; path.rename(retained); path.symlink_to(self.outside, target_is_directory=True)
        with patch.object(m.os, 'readlink', side_effect=AssertionError('No symlink target authority')), self.assertRaises(m.Refusal):
            self.scan_original_fixture(selection)
        path.unlink(); retained.rename(path)
        original = m.os.listdir; changed = []
        def listdir(fd):
            result = original(fd)
            if isinstance(fd, int) and self.key_fd(fd) == self.key(path) and not changed:
                changed.append(True); path.rename(retained); path.mkdir(mode=0o755); self.own(path, 0, 1000)
            return result
        with patch.object(m.os, 'listdir', side_effect=listdir), self.assertRaises(m.Refusal): self.scan_original_fixture(selection)
        self.assertTrue(retained.exists()); self.assertTrue(path.exists())

    def test_original_fixture_does_not_authorize_same_gid_elsewhere_or_private_domains(self):
        selection = self.original_fixture_selection(); foreign = self.scope / 'foreign-operator-group'
        foreign.mkdir(mode=0o750); self.own(foreign, 0, 1000)
        with self.assertRaises(m.Refusal): self.scan_original_fixture(selection)
        foreign.rmdir(); private = Path(next(row['volumeRoot'] for row in self.rows if row['name'] == 'apps')) / 'foreign-group'
        private.mkdir(mode=0o700); self.own(private, 0, 1000)
        with self.assertRaises(m.Refusal): self.scan_original_fixture(selection)
        self.assertTrue(private.exists()); self.assertFalse(self.cold_calls)

    @contextlib.contextmanager
    def synthetic_default_fixture(self, parent_present=True):
        network = {'name': 'podman', 'id': '2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9',
                   'driver': 'bridge', 'network_interface': 'podman0', 'created': '2026-10-24T16:58:52.144575746+11:00',
                   'dns_enabled': False, 'internal': False, 'ipv6_enabled': False, 'containers': {},
                   'ipam_options': {'driver': 'host-local'}, 'subnets': [{'subnet': '10.88.0.0/16', 'gateway': '10.88.0.1'}]}
        self.engine['networks']['podman'] = {'present': True, 'inspect': network, 'kernel': None}
        logical = Path('/etc/containers/networks/podman.json'); physical = self.physical(logical)
        if parent_present: physical.parent.mkdir(parents=True, exist_ok=True); physical.parent.chmod(0o755)
        original = m.source_ancestry
        def ancestry(path): return original(self.physical(path) if path.is_relative_to(logical.parent) else path)
        with patch.object(m, 'source_ancestry', side_effect=ancestry), patch.object(m, 'fd_mount_id', return_value=123):
            yield network, physical

    def test_default_network_clock_only_absent_builtin_is_stable_across_fresh_plans(self):
        with self.synthetic_default_fixture() as (_, path):
            original = self.engine_call; count = 0
            def clock(tool, args, mutate=False):
                nonlocal count
                code, body = original(tool, args, mutate)
                if tool == 'podman' and args == ['network', 'inspect', 'podman']:
                    count += 1; value = json.loads(body); value[0]['created'] = '2026-10-24T16:58:52.' + str(144575746 + count * 1000) + '+11:00'
                    body = json.dumps(value)
                return code, body
            with patch.object(m, 'cold_call', side_effect=clock):
                first = self.review(); second = self.review()
                self.assertEqual(first['planSha256'], second['planSha256'])
                record = first['plan']['rootfulDefault']['unselectedNetworks']['podman']
                self.assertEqual(record['volatileFields'], ['created']); self.assertIsNone(record['definitionSource']['file'])
                self.assertEqual(record['identityKind'], 'source-absent-netavark-in-memory-default')
                m.issue_stopped_lease(self.root, self.intent, first['planSha256'])
            self.assertFalse(path.exists()); self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_default_network_clock_present_definition_keeps_created_and_original_source_stat(self):
        with self.synthetic_default_fixture() as (network, path):
            self.put(path, b'protected config body NOT read')
            original = m.read_at
            def no_body(fd, name, **kwargs):
                self.assertNotEqual(name, 'podman.json'); return original(fd, name, **kwargs)
            with patch.object(m, 'read_at', side_effect=no_body):
                first = self.review(); record = first['plan']['rootfulDefault']['unselectedNetworks']['podman']
                self.assertNotIn('volatileFields', record); self.assertIsNotNone(record['definitionSource']['file'])
                network['created'] = '2026-10-24T16:58:52.162932277+11:00'
                second = self.review(); self.assertNotEqual(first['planSha256'], second['planSha256'])
                with self.assertRaises(m.Refusal): m.issue_stopped_lease(self.root, self.intent, first['planSha256'])
            self.assertEqual(path.read_bytes(), b'protected config body NOT read')

    def test_default_network_clock_every_nonclock_field_and_unknown_metadata_retains_cas(self):
        with self.synthetic_default_fixture() as (network, _):
            original = copy.deepcopy(network); first = self.review()
            changes = [{'id': 'e' * 64}, {'subnets': [{'subnet': '10.99.0.0/16'}]}, {'ipam_options': {'driver': 'none'}},
                       {'containers': {'consumer': {}}}, {'opaque-new-field': 'not-ignored'}, {'driver': 'macvlan'},
                       {'network_interface': 'other0'}, {'dns_enabled': True}, {'internal': True}, {'ipv6_enabled': True}]
            for change in changes:
                network.clear(); network.update(copy.deepcopy(original)); network.update(change)
                with self.subTest(change=change):
                    self.assertNotEqual(first['planSha256'], self.review()['planSha256'])
                    with self.assertRaises(m.Refusal): m.issue_stopped_lease(self.root, self.intent, first['planSha256'])
            self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_default_network_clock_file_creation_during_native_inspect_refuses(self):
        with self.synthetic_default_fixture() as (_, path):
            original = self.engine_call; count = 0
            def call(tool, args, mutate=False):
                nonlocal count
                result = original(tool, args, mutate)
                if tool == 'podman' and args == ['network', 'inspect', 'podman']:
                    count += 1
                    if count == 2: self.put(path, b'external new real definition')
                return result
            with patch.object(m, 'cold_call', side_effect=call), self.assertRaises(m.Refusal): self.review()
            self.assertEqual(path.read_bytes(), b'external new real definition')
            self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_default_network_clock_original_parent_namespace_replacement_refuses(self):
        with self.synthetic_default_fixture() as (_, path):
            original = self.engine_call; count = 0
            def call(tool, args, mutate=False):
                nonlocal count
                result = original(tool, args, mutate)
                if tool == 'podman' and args == ['network', 'inspect', 'podman']:
                    count += 1
                    if count == 2:
                        path.parent.rename(path.parent.with_name('retained-original-networks')); path.parent.mkdir(mode=0o755)
                return result
            with patch.object(m, 'cold_call', side_effect=call), self.assertRaises(m.Refusal): self.review()
            self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_default_network_clock_source_absence_unobserved_parent_never_normalizes(self):
        with self.synthetic_default_fixture(parent_present=False) as (network, _):
            record = m._unselected_network_record('podman', network)
            self.assertNotIn('volatileFields', record); self.assertEqual(record['sha256'], m.sha(m.canonical(network)))

    def test_default_network_clock_other_names_ids_shapes_and_invalid_timestamps_never_normalize(self):
        with self.synthetic_default_fixture() as (network, _):
            changes = [{'name': 'foreign'}, {'id': 'f' * 64}, {'created': 'yesterday'},
                       {'created': '2026-99-99T16:58:52+11:00'}, {'future': 'unknown'}, {'subnets': []}]
            original = copy.deepcopy(network)
            for change in changes:
                network.clear(); network.update(copy.deepcopy(original)); network.update(change)
                with self.subTest(change=change), patch.object(m, '_default_network_definition', side_effect=AssertionError('No synthetic classification')):
                    record = m._unselected_network_record(network['name'], network)
                    self.assertEqual(record['sha256'], m.sha(m.canonical(network))); self.assertNotIn('volatileFields', record)

    def test_default_network_clock_real_definition_inode_and_mount_change_refuse(self):
        with self.synthetic_default_fixture() as (_, path):
            self.put(path, b'real network config'); first = self.review()
            body = path.read_bytes(); path.rename(path.with_name('retained-original-podman.json')); self.put(path, body)
            with self.assertRaises(m.Refusal): m.issue_stopped_lease(self.root, self.intent, first['planSha256'])
            first = self.review()
            with patch.object(m, 'fd_mount_id', return_value=124), self.assertRaises(m.Refusal):
                m.issue_stopped_lease(self.root, self.intent, first['planSha256'])
            self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_buildah_null_inventory_accepts_only_exact_empty_serialization_and_retains_raw_proof(self):
        for value in (None, []):
            self.engine['buildah'] = value
            plan = self.review()['plan']
            self.assertEqual(plan['rootfulDefault']['buildahContainers'], value)
            encoded = json.loads(m.canonical(plan))
            self.assertEqual(encoded['rootfulDefault']['buildahContainers'], value)
            if value is None: self.assertIsNone(encoded['rootfulDefault']['buildahContainers'])
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_buildah_null_inventory_nonempty_and_unknown_shapes_refuse(self):
        for value in ([{'id': 'real-data'}], [None], {}, False, 0, '', 'null'):
            self.engine['buildah'] = value
            with self.subTest(value=value), self.assertRaises(m.Refusal): self.review()
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_buildah_null_inventory_command_error_and_malformed_json_never_empty(self):
        original = self.engine_call
        for code, body in ((1, 'null'), (125, 'null'), (0, ''), (0, 'null extra'), (0, 'null\nnull')):
            def call(tool, args, mutate=False):
                return (code, body) if tool == 'buildah' and args == ['containers', '--json'] else original(tool, args, mutate)
            with self.subTest(code=code, body=body), patch.object(m, 'cold_call', side_effect=call), self.assertRaises(m.Refusal): self.review()
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_buildah_null_inventory_does_not_normalize_other_inventory_interfaces(self):
        self.engine['buildah'] = None; original = self.engine_call
        for selected in (('podman', ['ps', '--all', '--no-trunc', '--format=json']),
                         ('podman', ['volume', 'ls', '--format=json']), ('buildah', ['info']),
                         ('buildah', ['images', '--all', '--no-trunc', '--json']),
                         ('podman', ['network', 'ls', '--format=json'])):
            def call(tool, args, mutate=False):
                return (0, 'null') if (tool, args) == selected else original(tool, args, mutate)
            with self.subTest(command=selected), patch.object(m, 'cold_call', side_effect=call), self.assertRaises(m.Refusal): self.review()
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_buildah_null_inventory_serialization_change_invalidates_reviewed_plan(self):
        self.engine['buildah'] = None; reviewed = self.review()
        self.engine['buildah'] = []
        with self.assertRaises(m.Refusal): m.issue_stopped_lease(self.root, self.intent, reviewed['planSha256'])
        self.assertNotEqual(reviewed['planSha256'], self.review()['planSha256'])
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_buildah_null_inventory_still_requires_original_default_engine_context(self):
        self.engine['buildah'] = None
        original = self.engine_info['store']['graphRoot']; self.engine_info['store']['graphRoot'] = '/foreign/data'
        with self.assertRaises(m.Refusal): self.review()
        self.engine_info['store']['graphRoot'] = original
        original = self.buildah_info['store']['GraphRoot']; self.buildah_info['store']['GraphRoot'] = '/foreign/buildah'
        with self.assertRaises(m.Refusal): self.review()
        self.buildah_info['store']['GraphRoot'] = original
        with patch.object(m, 'root_runtime_identity', side_effect=m.Refusal('changed kernel namespace')), self.assertRaises(m.Refusal): self.review()
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_rootful_default_images_cache_and_selected_network_cold(self):
        network = self.add_root_network()
        original = self.engine_call; observed = []
        def call(tool, args, mutate=False):
            if mutate:
                self.assertEqual(len(list((self.root / '.host-clean-reset').glob('*-intent.json'))), 1)
                observed.append(list(args))
            return original(tool, args, mutate)
        with patch.object(m, 'cold_call', new=call): result = self.run_reset()
        self.assertTrue(result['rootImageCold']); self.assertTrue(result['selectedNetworkClosure'])
        self.assertTrue(result['rootfulStoreColdAcceptance']); self.assertFalse(result['applicationAcceptance'])
        self.assertFalse(network['present']); self.assertIsNone(network['kernel'])
        self.assertEqual(observed, [['image', 'prune', '--all', '--build-cache', '--force'], ['network', 'rm', 'webservices_safe']])

    def test_rootful_unselected_network_and_kernel_definition_preserved(self):
        network = self.add_root_network(); foreign = copy.deepcopy(network)
        foreign['inspect'].update(name='podman', id='f' * 64, network_interface='podman0')
        foreign['kernel']['ifindex'] = 20
        foreign['kernel']['link'].update(ifindex=20, ifname='podman0')
        foreign['kernel']['addresses'][0].update(ifindex=20, ifname='podman0')
        foreign['kernel']['routes'][0]['dev'] = 'podman0'
        self.engine['networks']['podman'] = foreign; before = copy.deepcopy(foreign)
        self.run_reset(); self.assertEqual(foreign, before)
        self.assertFalse(any(mutate and args == ['network', 'rm', 'podman'] for _, args, mutate in self.cold_calls))

    def test_rootful_containers_volumes_buildah_data_refuse_before_mutation(self):
        for field in ('containers', 'volumes', 'buildah'):
            with self.subTest(field=field):
                self.engine[field] = [{'id': 'synthetic-data-not-disposable'}]
                self.denied(); self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))
                self.engine[field] = []

    def test_rootful_foreign_store_driver_context_and_config_refused(self):
        original = copy.deepcopy(self.engine_info)
        changes = [('store', 'graphRoot', '/other/store'), ('store', 'runRoot', '/other/run'),
                   ('store', 'graphDriverName', 'vfs'), ('store', 'configFile', '/caller/store.conf'),
                   ('store', 'volumePath', '/other/data'), ('host', 'networkBackend', 'cni')]
        for section, field, value in changes:
            with self.subTest(field=field):
                self.engine_info = copy.deepcopy(original); self.engine_info[section][field] = value; self.denied()
        self.engine_info = copy.deepcopy(original); self.engine_info['host']['security']['rootless'] = True; self.denied()
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_rootful_buildah_foreign_default_store_is_not_zero_proof(self):
        for field, value in (('GraphRoot', '/other/graph'), ('RunRoot', '/other/run'), ('GraphDriverName', 'vfs')):
            with self.subTest(field=field):
                original = self.buildah_info['store'][field]; self.buildah_info['store'][field] = value
                self.denied(); self.buildah_info['store'][field] = original
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_rootful_plan_image_and_control_cas_changes_refuse(self):
        reviewed = self.review(); lease = m.issue_stopped_lease(self.root, self.intent, reviewed['planSha256'])
        self.engine['images'].append('e' * 64)
        with self.assertRaises(m.Refusal): m.execute(self.root, self.intent, reviewed['planSha256'], lease)
        self.engine['images'].pop(); self.root_context['controls']['system']['sha256'] = 'd' * 64
        with self.assertRaises(m.Refusal): m.issue_stopped_lease(self.root, self.intent, reviewed['planSha256'])
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_rootful_process_or_namespace_failure_has_no_mutation(self):
        with patch.object(m, 'root_runtime_identity', side_effect=m.Refusal('synthetic root runtime remains')): self.denied()
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def failed_result(self):
        return json.loads(next((self.root / '.host-clean-reset').glob('*-result.json')).read_text())

    def test_rootful_failed_prune_retains_failed_evidence_and_data(self):
        self.engine['pruneFails'] = True
        with self.assertRaises(m.Refusal): self.run_reset()
        result = self.failed_result(); self.assertFalse(result['rootfulStoreColdAcceptance']); self.assertFalse(result['completeCleanReset'])
        self.assertTrue((Path(self.rows[0]['graphRoot']) / 'overlay/layer/data').exists())
        self.assertEqual((self.root / '.install-intent.json').read_bytes(), self.original_intent)

    def test_rootful_remaining_orphan_layers_never_get_external_prune(self):
        self.engine['leaveLayers'] = True
        with self.assertRaisesRegex(m.Refusal, 'layer metadata remains'): self.run_reset()
        self.assertFalse(self.failed_result()['rootfulStoreColdAcceptance'])
        self.assertFalse(any('--external' in args or 'system' in args for _, args, _ in self.cold_calls))

    def test_rootful_orphan_disk_layer_not_hidden_by_empty_engine_metadata(self):
        for field in ('orphanLayers', 'orphanImageDirs'):
            with self.subTest(field=field):
                self.engine[field] = ['e' * 64]
                with self.assertRaisesRegex(m.Refusal, 'orphan image/layer directories'): self.run_reset()
                self.assertFalse(self.failed_result()['rootImageCold'])
                self.assertFalse(self.failed_result()['rootfulStoreColdAcceptance'])
                self.assertEqual(self.engine[field], ['e' * 64]); self.engine[field] = []
        self.assertFalse(any('--external' in args for _, args, _ in self.cold_calls))

    def test_rootful_selected_network_remove_failure_never_forced(self):
        self.add_root_network(); self.engine['rmFails'] = True
        with self.assertRaises(m.Refusal): self.run_reset()
        result = self.failed_result(); self.assertTrue(result['rootImageCold']); self.assertFalse(result['selectedNetworkClosure'])
        self.assertFalse(result['rootfulStoreColdAcceptance'])
        self.assertEqual([args for _, args, mutate in self.cold_calls if mutate and args[:2] == ['network', 'rm']],
                         [['network', 'rm', 'webservices_safe']])

    def test_rootful_residual_kernel_bridge_fails_not_manual_cleanup(self):
        network = self.add_root_network(); self.engine['leaveBridge'] = True
        with self.assertRaisesRegex(m.Refusal, 'network/kernel closure'): self.run_reset()
        self.assertFalse(network['present']); self.assertIsNotNone(network['kernel'])
        result = self.failed_result(); self.assertTrue(result['rootImageCold']); self.assertFalse(result['rootfulStoreColdAcceptance'])
        self.assertFalse(any(tool == 'ip' and mutate for tool, _, mutate in self.cold_calls))

    def test_rootful_unknown_kernel_ports_addresses_routes_refuse(self):
        network = self.add_root_network(); original = copy.deepcopy(network['kernel'])
        for field, value in (('ports', [{'ifname': 'foreign-veth'}]),
                             ('addresses', [{'ifindex': 10, 'ifname': 'podman5', 'addr_info': [{'local': '192.0.2.9'}]}]),
                             ('routes', [{'dev': 'podman5', 'dst': 'default', 'gateway': '10.20.0.9'}])):
            with self.subTest(field=field):
                network['kernel'] = copy.deepcopy(original); network['kernel'][field] = value; self.denied()
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_rootful_unselected_network_bridge_alias_refused(self):
        network = self.add_root_network(); foreign = copy.deepcopy(network)
        foreign['inspect'].update(name='authored-network', id='f' * 64)
        self.engine['networks']['authored-network'] = foreign; self.denied()
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_rootful_selected_kernel_inode_equivalent_ifindex_change_refused(self):
        network = self.add_root_network(); reviewed = self.review()
        lease = m.issue_stopped_lease(self.root, self.intent, reviewed['planSha256'])
        network['kernel']['ifindex'] = 11
        network['kernel']['link']['ifindex'] = 11; network['kernel']['addresses'][0]['ifindex'] = 11
        with self.assertRaises(m.Refusal): m.execute(self.root, self.intent, reviewed['planSha256'], lease)
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_rootful_absent_network_without_inspect_provenance_not_cold(self):
        network = self.add_root_network(); network['present'] = False
        with self.assertRaisesRegex(m.Refusal, 'inspect provenance'): self.run_reset()
        result = self.failed_result(); self.assertTrue(result['rootImageCold'])
        self.assertFalse(result['selectedNetworkClosure']); self.assertFalse(result['rootfulStoreColdAcceptance'])

    def test_rootful_exact_durable_inspect_provenance_supports_fresh_review(self):
        network = self.add_root_network(); self.engine['leaveBridge'] = True
        with self.assertRaises(m.Refusal): self.run_reset()
        # Model a separately resolved OWNER dependency. Backend never deletes
        # this residual interface; fresh review must verify its actual absence.
        network['kernel'] = None
        result = self.run_reset()
        self.assertTrue(result['rootfulStoreColdAcceptance'])
        self.assertEqual(sum(args[:2] == ['network', 'rm'] and mutate for _, args, mutate in self.cold_calls), 1)

    def test_rootful_consumer_after_image_checkpoint_refuses_next_mutator(self):
        self.add_root_network(); original = m.write_evidence
        def write(fd, name, value):
            original(fd, name, value)
            if '-progress-' in name and 'rootfulAfterImages' in value:
                self.engine['containers'] = [{'id': 'foreign-new-writable-data'}]
        with patch.object(m, 'write_evidence', side_effect=write):
            with self.assertRaises(m.Refusal): self.run_reset()
        self.assertFalse(any(args[:2] == ['network', 'rm'] and mutate for _, args, mutate in self.cold_calls))
        self.assertFalse(self.failed_result()['rootfulStoreColdAcceptance'])

    def test_rootful_final_image_repopulation_never_counts_cold(self):
        original = m.write_evidence
        def write(fd, name, value):
            original(fd, name, value)
            if '-progress-' in name and str(self.scope) in value.get('emptied', []): self.engine['images'] = ['e' * 64]
        with patch.object(m, 'write_evidence', side_effect=write):
            with self.assertRaises(m.Refusal): self.run_reset()
        self.assertFalse(self.failed_result()['rootfulStoreColdAcceptance'])

    def test_rootful_dispatch_sanitizes_context_and_suppresses_mutator_output(self):
        def child(command, **kwargs):
            self.assertEqual(command, ['/usr/bin/podman', 'image', 'prune', '--all', '--build-cache', '--force'])
            self.assertEqual(kwargs['env'], m.ROOT_ENV)
            self.assertNotIn('CONTAINERS_STORAGE_CONF', kwargs['env'])
            self.assertEqual(kwargs['stderr'], m.subprocess.DEVNULL)
            self.assertEqual(kwargs['stdout'], m.subprocess.DEVNULL)
            return types.SimpleNamespace(returncode=0, stdout='synthetic output must never escape')
        with patch.object(m.subprocess, 'run', side_effect=child):
            self.assertEqual(REAL_COLD_CALL('podman', ['image', 'prune', '--all', '--build-cache', '--force'], True), (0, ''))

    def mapped_cold_path(self, path, contents=False):
        path = self.virtual / str(path).lstrip('/')
        return REAL_COLD_PATH(path, contents)

    def system_storage_config(self, suffix=''):
        path = self.virtual / 'usr/share/containers/storage.conf'
        self.put(path, ('[storage]\ndriver="overlay"\ngraphroot="' + m.ROOT_GRAPH + '"\nrunroot="' + m.ROOT_RUN
                        + '"\n[storage.options]\nadditionalimagestores=[]\n' + suffix).encode())
        return path

    def test_rootful_default_system_config_real_fd_and_absence_pins(self):
        path = self.system_storage_config()
        auth = self.virtual / 'root/.config/containers/auth.json'; self.put(auth, b'synthetic auth must stay unread')
        forbidden = self.key(auth); read = os.read
        def guarded(fd, count):
            self.assertNotEqual(self.key_fd(fd), forbidden); return read(fd, count)
        with patch.object(m, 'cold_path', new=self.mapped_cold_path), patch.object(m.os, 'read', side_effect=guarded):
            context = REAL_CONTEXT()
        self.assertIn('/usr/share/containers/storage.conf', context['storageConfigs'])
        self.assertEqual(context['storageConfigs']['/usr/share/containers/storage.conf']['sha256'], m.sha(path.read_bytes()))
        self.assertEqual(auth.read_bytes(), b'synthetic auth must stay unread')

    def test_rootful_default_system_config_foreign_or_hardlinked_refused(self):
        path = self.system_storage_config()
        with patch.object(m, 'cold_path', new=self.mapped_cold_path):
            path.write_bytes(path.read_bytes().replace(b'additionalimagestores=[]', b'additionalimagestores=["/foreign"]'))
            with self.assertRaises(m.Refusal): REAL_CONTEXT()
            self.system_storage_config(); self.own(path, 1000)
            with self.assertRaises(m.Refusal): REAL_CONTEXT()
            self.own(path, 0); os.link(path, path.with_name('external-alias'))
            with self.assertRaises(m.Refusal): REAL_CONTEXT()

    def test_rootful_user_config_presence_refused_without_reading_body(self):
        self.system_storage_config()
        path = self.virtual / 'root/.config/containers/containers.conf'; self.put(path, b'synthetic private steering')
        forbidden = self.key(path); read = os.read
        def guarded(fd, count):
            self.assertNotEqual(self.key_fd(fd), forbidden); return read(fd, count)
        with patch.object(m, 'cold_path', new=self.mapped_cold_path), patch.object(m.os, 'read', side_effect=guarded):
            with self.assertRaises(m.Refusal): REAL_CONTEXT()

    def test_rootful_layer_metadata_real_fd_no_layer_data_walk(self):
        path = self.virtual / ('var/lib/containers/storage/overlay-layers/layers.json')
        self.put(path, json.dumps([{'id': 'a' * 64}]).encode())
        with patch.object(m, 'cold_path', new=self.mapped_cold_path):
            self.assertEqual(REAL_LAYERS()['ids'], ['a' * 64])
            path.write_text('[]'); self.assertEqual(REAL_LAYERS()['ids'], [])
            os.link(path, path.with_name('external-layer-metadata-alias'))
            with self.assertRaises(m.Refusal): REAL_LAYERS()

    def test_rootful_disk_layer_real_fd_no_descent_and_lower_links_pinned(self):
        root = self.virtual / 'var/lib/containers/storage/overlay'; layer = root / ('a' * 64)
        (layer / 'diff').mkdir(parents=True); (root / 'l').mkdir()
        for path in (root.parent.parent.parent.parent, root.parent.parent.parent, root.parent.parent, root.parent,
                     root, layer, layer / 'diff', root / 'l'):
            path.chmod(0o700)
        # A nested fixture special node would fail any global data walk. This
        # observer may only stat the layer's top-level directory, never descend.
        os.mkfifo(layer / 'diff/protected-data-fifo', 0o600)
        (root / 'l/SHORT').symlink_to('../' + 'a' * 64 + '/diff')
        snapshot = m.layer_disk_inventory()
        self.assertEqual(snapshot['layers'], ['a' * 64]); self.assertEqual(set(snapshot['lowerLinks']), {'SHORT'})
        self.assertTrue((layer / 'diff/protected-data-fifo').exists())
        (root / 'l/SHORT').unlink(); (layer / 'diff/protected-data-fifo').unlink(); (layer / 'diff').rmdir(); layer.rmdir()
        snapshot = m.layer_disk_inventory(); self.assertEqual(snapshot['layers'], []); self.assertEqual(snapshot['lowerLinks'], {})
        images = root.parent / 'overlay-images'; images.mkdir(mode=0o700)
        data = images / ('b' * 64); data.mkdir(mode=0o700)
        os.mkfifo(data / 'protected-image-data-fifo', 0o600)
        image_snapshot = m.image_disk_inventory()
        self.assertEqual(image_snapshot['ids'], ['b' * 64])
        self.assertFalse(m.root_images_cold({'images': [], 'buildahImages': [],
            'layers': {'ids': [], 'disk': snapshot, 'imageDirectories': image_snapshot}}))
        self.assertTrue((data / 'protected-image-data-fifo').exists())

    def test_rootful_root_process_namespace_and_api_gate_ignores_uid1001(self):
        proc = self.base / 'model-root-proc'; (proc / '101').mkdir(parents=True)
        status = proc / '101/status'
        status.write_text('Uid:\t1001 1001 1001 1001\n')
        (proc / '101/exe').symlink_to('/usr/bin/conmon')
        path, readlink = Path, os.readlink
        def paths(value): return proc if str(value) == '/proc' else path(value)
        def link(value):
            if str(value).startswith(('/proc/self/ns/', '/proc/1/ns/')):
                return str(value).split('/')[-1] + ':[model-host]'
            return readlink(value)
        def query(args):
            unit = args[2]
            fields = dict(Id=unit, LoadState='not-found', ActiveState='inactive', SubState='dead', Job='', UnitFileState='not-found')
            # Absent units may omit type-specific PID properties. Socket units
            # have ControlPID, not the service-only MainPID property.
            if unit.endswith('.service'): fields['MainPID'] = '0'
            return types.SimpleNamespace(returncode=1, stdout='\n'.join(key + '=' + value for key, value in fields.items()))
        with patch.object(m, 'Path', side_effect=paths), patch.object(m.os, 'readlink', side_effect=link), patch.object(m, 'run_read', side_effect=query):
            self.assertEqual(set(REAL_ROOT_RUNTIME()), {'user', 'net'})
            status.write_text('Uid:\t0 0 0 0\n')
            with self.assertRaises(m.Refusal): REAL_ROOT_RUNTIME()
            status.write_text('Uid:\t1001 1001 1001 1001\n')
            with patch.object(m, 'run_read', return_value=types.SimpleNamespace(returncode=1, stdout='')):
                with self.assertRaises(m.Refusal): REAL_ROOT_RUNTIME()
            active = 'Id=podman.socket\nLoadState=loaded\nActiveState=active\nSubState=listening\nControlPID=0\nJob=\nUnitFileState=enabled'
            with patch.object(m, 'run_read', return_value=types.SimpleNamespace(returncode=0, stdout=active)):
                with self.assertRaises(m.Refusal): REAL_ROOT_RUNTIME()
            with patch.object(m.os, 'readlink', side_effect=lambda value: 'foreign-net:[9]' if str(value) == '/proc/self/ns/net' else link(value)):
                with self.assertRaises(m.Refusal): REAL_ROOT_RUNTIME()
        self.assertTrue((proc / '101/exe').is_symlink())

    def test_rootful_candidate_and_previous_source_network_union(self):
        self.add_root_network('old', 'podman5')
        previous = self.root / 'releases/r0'; previous.mkdir(mode=0o700)
        for path in sorted(self.release.rglob('*'), key=lambda value: len(value.parts)):
            target = previous / path.relative_to(self.release)
            if path.is_dir(): target.mkdir(mode=0o700)
            else: self.put(target, path.read_bytes(), stat.S_IMODE(REAL_STAT(path).st_mode))
        receipt = json.loads((previous / 'installation-receipt.json').read_text())
        receipt['release'] = str(previous); self.put(previous / 'installation-receipt.json', receipt, 0o600)
        edge = self.release / 'quadlet/rootful/webservices-edge.container'
        edge.write_bytes(edge.read_bytes().replace(b'Network=webservices-old.network\n', b''))
        (self.release / 'quadlet/rootful/webservices-old.network').unlink()
        self.ir['networks'] = {}; self.receipt_extra['previousRelease'] = str(previous)
        self.add_root_network('new', 'podman6')
        reviewed = self.review()
        self.assertEqual(set(reviewed['plan']['rootfulDefault']['networks']), {'webservices_old', 'webservices_new'})
        result = self.run_reset(reviewed); self.assertTrue(result['rootfulStoreColdAcceptance'])
        self.assertEqual({args[-1] for _, args, mutate in self.cold_calls if mutate and args[:2] == ['network', 'rm']},
                         {'webservices_old', 'webservices_new'})

    def test_rootful_evidence_reserve_refuses_without_mutation(self):
        reviewed = self.review(); lease = m.issue_stopped_lease(self.root, self.intent, reviewed['planSha256'])
        space = types.SimpleNamespace(f_bavail=0, f_frsize=4096, f_favail=0)
        with patch.object(m.os, 'statvfs', return_value=space):
            with self.assertRaises(m.Refusal): m.execute(self.root, self.intent, reviewed['planSha256'], lease)
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))
        self.assertFalse((self.root / '.host-clean-reset').exists())

    def legacy_dropin(self, actor=None, empty=False):
        logical = Path('/etc/systemd/system') if actor is None else Path(actor['home']) / '.config/systemd/user'
        parent = self.physical(logical / 'webservices.target.d')
        if not parent.exists(): parent.mkdir(mode=0o755)
        parent.chmod(0o755); uid = 0 if actor is None else actor['uid']; self.own(parent, uid)
        child = parent / '10-runtime-env.conf'
        if not empty:
            self.put(child, b'[Unit]\nRequires=webservices-runtime-env.service\nAfter=webservices-runtime-env.service\n')
            self.own(child, uid)
        return parent, child

    def test_legacy_dropin_file_and_exact_empty_parent_closed_for_publisher(self):
        root, root_file = self.legacy_dropin()
        actor, actor_file = self.legacy_dropin(self.actors[0])
        unrelated = self.physical(Path('/etc/systemd/system/authored.target.d')); unrelated.mkdir(mode=0o755)
        wants = self.physical(Path('/etc/systemd/system/default.target.wants'))
        self.put(wants / 'authored.service', b'synthetic unrelated activation')
        result = self.run_reset()
        self.assertFalse(root.exists()); self.assertFalse(actor.exists())
        self.assertTrue(unrelated.is_dir()); self.assertTrue((wants / 'authored.service').exists())
        self.assertIn('/etc/systemd/system/webservices.target.d', result['deletedExternalDirectories'])
        self.assertIn('/etc/systemd/system/webservices.target.d/10-runtime-env.conf', result['deletedExternalFiles'])
        self.assertTrue(result['completeCleanReset'])

    def test_legacy_dropin_already_empty_exact_source_parent_closed(self):
        parent, _ = self.legacy_dropin(empty=True)
        result = self.run_reset()
        self.assertFalse(parent.exists()); self.assertIn('/etc/systemd/system/webservices.target.d', result['deletedExternalDirectories'])

    def test_legacy_dropin_foreign_nonempty_parent_preserved_before_any_mutation(self):
        parent, child = self.legacy_dropin(); foreign = parent / 'authored.conf'
        self.put(foreign, b'synthetic authored data')
        self.denied(); self.assertTrue(child.exists()); self.assertEqual(foreign.read_bytes(), b'synthetic authored data')
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_legacy_dropin_foreign_metadata_or_readonly_counterfeit_refused(self):
        parent, _ = self.legacy_dropin(empty=True)
        self.own(parent, 1000); self.denied(); self.own(parent, 0)
        for mode in (0o555, 0o750, 0o700):
            with self.subTest(mode=mode): parent.chmod(mode); self.denied(); self.assertTrue(parent.exists())
        parent.chmod(0o755); self.set_acl(parent, [[2, 0, 1000]])
        self.denied(); self.assertTrue(parent.exists())
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_legacy_dropin_parent_inode_swap_after_lease_is_preserved(self):
        parent, child = self.legacy_dropin()
        reviewed = self.review(); lease = m.issue_stopped_lease(self.root, self.intent, reviewed['planSha256'])
        kept = parent.with_name('saved-original-fixture-parent'); parent.rename(kept)
        self.legacy_dropin()
        with self.assertRaises(m.Refusal): m.execute(self.root, self.intent, reviewed['planSha256'], lease)
        self.assertTrue(child.exists()); self.assertTrue((kept / child.name).exists())
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_legacy_dropin_parent_repopulation_during_claim_is_not_removed(self):
        parent, _ = self.legacy_dropin(); original = m.claim; kept = []
        def claim(fd, name, destination, expected):
            pin = original(fd, name, destination, expected)
            if name == 'webservices.target.d':
                target = parent.parent / destination
                self.put(target / 'authored-after-claim.conf', b'synthetic protected late file')
                kept.append(target)
            return pin
        with patch.object(m, 'claim', side_effect=claim):
            with self.assertRaises(m.Refusal): self.run_reset()
        self.assertEqual(len(kept), 1)
        self.assertEqual((kept[0] / 'authored-after-claim.conf').read_bytes(), b'synthetic protected late file')
        self.assertFalse(self.failed_result()['completeCleanReset'])

    def test_legacy_updater_compat_artifacts_alone_are_not_installed_ownership(self):
        for actor in self.actors:
            self.physical(Path(actor['home']) / '.config/systemd/user/webservices.target.d').rmdir()
        self.patch(m, 'LEGACY_SOURCE_INSTALLERS', new=frozenset())
        # Fresh native profile + shipped compatibility artifacts is valid when
        # the old namespace is absent, but must never adopt an installed file.
        self.review()
        path = self.physical(Path('/usr/local/sbin/webservices-auto-update'))
        self.put(path, (self.release / 'ops/webservices-auto-update').read_bytes(), 0o755)
        self.denied(); self.assertTrue(path.exists())
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))
        # Even a recognized OLD previous source cannot re-grant its namespace
        # after exact retired-clean disposition. The current profile is new.
        previous = self.root / 'releases/retired'; previous.mkdir(mode=0o700)
        old_installer = self.release / 'ops/install-podman-bundle.sh'
        digest = m.sha(old_installer.read_bytes())
        for source in sorted(self.release.rglob('*'), key=lambda value: len(value.parts)):
            target = previous / source.relative_to(self.release)
            if source.is_dir(): target.mkdir(mode=0o700)
            else: self.put(target, source.read_bytes(), stat.S_IMODE(REAL_STAT(source).st_mode))
        receipt = json.loads((previous / 'installation-receipt.json').read_text())
        receipt.update(release=str(previous), phase='retired-clean')
        self.put(previous / 'installation-receipt.json', receipt, 0o600)
        new_body = old_installer.read_bytes() + b'\n# isolated fixture new non-legacy generation\n'
        self.put(old_installer, new_body)
        m.RECOGNIZED['install-podman-bundle.sh'].add(m.sha(new_body))
        self.patch(m, 'LEGACY_SOURCE_INSTALLERS', new=frozenset({digest}))
        self.receipt_extra['previousRelease'] = str(previous); self.seal()
        self.denied(); self.assertTrue(path.exists())
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_legacy_updater_arbitrary_matching_source_and_installed_body_refused(self):
        path = self.physical(Path('/usr/local/sbin/webservices-auto-update'))
        self.put(path, b'synthetic authored updater', 0o755)
        self.put(self.release / 'ops/webservices-auto-update', path.read_bytes(), 0o755)
        self.denied(); self.assertEqual(path.read_bytes(), b'synthetic authored updater')
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_legacy_updater_exact_three_files_removed_without_foreign_namespace_sweep(self):
        paths = []
        for filename in m.UPDATER_SOURCES:
            logical = (Path('/usr/local/sbin') if filename == 'webservices-auto-update' else Path('/etc/systemd/system')) / filename
            path = self.physical(logical); self.put(path, (self.release / 'ops' / filename).read_bytes(),
                0o755 if filename == 'webservices-auto-update' else 0o644); paths.append(path)
        foreign = self.physical(Path('/etc/systemd/system/webservices-authored-update.timer'))
        self.put(foreign, b'synthetic unrelated timer')
        self.run_reset(); self.assertTrue(all(not path.exists() for path in paths)); self.assertTrue(foreign.exists())

    def native_unit_fixture(self, populated=False):
        if populated: self.ir['services']['edge']['environment'] = {'SYNTHETIC': 'SYNTHETIC_VALUE_DO_NOT_RECORD'}
        pins = {}
        for name in m.RUNTIME_ENV_RENDERER_PINS:
            data = (OPS / name).read_bytes(); self.put(self.canonical_ops / name, data)
            pins[name] = frozenset({m.sha(data)})
        self.patch(m, 'RUNTIME_ENV_RENDERER_PINS', new=pins)
        self.patch(m, 'fd_mount_id', return_value=123)
        self.bundle_extra = {'liveOps': {'ops/' + name: next(iter(values)) for name, values in pins.items()}}
        self.seal(); inputs = json.loads((self.root / '.install-intent.json').read_text())['inputs']
        marker = m.sha((self.scope / m.MARKER).read_bytes())
        self.receipt_extra['rootfulEnvCustody'] = dict(kind='rootful-environment-custody', release=str(self.release),
            inputs=inputs, scopeMarkerSha256=marker, files={})
        root = dict(schemaVersion=1, kind='rootful-persistent-environment', status='completed', release=str(self.release),
            inputs=inputs, scopeMarkerSha256=marker, stateStore=str(self.root / 'runtime-env'), runtimeDeferred=True, files={}, store=None,
            sourceCustodySha256=m.sha(m.canonical(self.receipt_extra['rootfulEnvCustody'])), activationAuthorized=False, readinessAuthorized=False)
        if populated:
            path = self.root / 'runtime-env/edge.env'; self.put(path, b'SYNTHETIC=SYNTHETIC_VALUE_DO_NOT_RECORD\n', 0o600)
            path.parent.chmod(0o700); info = m.os.stat(path)
            seal = dict(dev=info.st_dev, ino=info.st_ino, uid=0, gid=0, mode=0o600, mountId=123,
                acl='', defaultAcl='', identity=m.fingerprint(info), sha256=m.sha(path.read_bytes()))
            info = m.os.stat(path.parent)
            root['store'] = dict(dev=info.st_dev, ino=info.st_ino, uid=0, gid=0, mode=0o700, mountId=123, acl='', defaultAcl='')
            root['files'] = {'edge.env': seal}; self.receipt_extra['rootfulEnvCustody']['files'] = root['files']
            root['sourceCustodySha256'] = m.sha(m.canonical(self.receipt_extra['rootfulEnvCustody']))
        self.receipt_extra['rootfulEnvironmentStoreHandoff'] = root; producers = {}; roles = {}
        for role, actor in [('rootful', None), *[('rootless-' + row['name'], row) for row in self.actors]]:
            uid, gid, user = (0, 0, 'root') if actor is None else (actor['uid'], actor['gid'], actor['user'])
            anchor = self.root if actor is None else Path(next(row['stateRoot'] for row in self.rows if row['name'] == actor['name']))
            runtime = '/run/webservices' if actor is None else '/run/user/' + str(uid) + '/webservices'
            source_sha = root['sourceCustodySha256']
            if actor is not None:
                producer = {'custodySha256': 'd' * 64}; source_sha = producer['custodySha256']
                producer['environmentStoreHandoff'] = dict(schemaVersion=1, kind='domain-persistent-environment', status='completed',
                    release=str(self.release), domain=actor['name'], uid=uid, gid=gid, inputs=inputs, scopeMarkerSha256=marker,
                    custodySha256=source_sha, sourceProjectionSha256=m.sha(m.canonical(producer)),
                    stateStore=str(anchor / 'runtime-env'), runtimeStore=runtime, runtimeDeferred=True,
                    store=None, files={}, activationAuthorized=False, readinessAuthorized=False)
                producers[actor['name']] = producer
            parent = self.release if actor is None else anchor / 'releases' / self.release.name
            roles[role] = dict(schemaVersion=1, kind='exact-runtime-environment', release=str(self.release), role=role,
                uid=uid, gid=gid, user=user, inputsSha256=m.sha(m.canonical(inputs)), scopeMarkerSha256=marker,
                sourceCustodySha256=source_sha, sourceAnchor=str(anchor), stateStore=str(anchor / 'runtime-env'),
                runtimeStore=runtime, custodyFile=str(parent / 'runtime-env-copy-custody.json'),
                custodyDirectories={}, sourceDirectories={}, files=root['files'] if actor is None else {},
                store=root['store'] if actor is None else None)
        self.receipt_extra['domainRuntimeProjections'] = producers
        self.seal()
        with m.locked(self.root): selection = m.binding(self.root, self.intent)
        renderer, _, _ = m.current_env_renderer(selection)
        custody = dict(schemaVersion=1, kind='native-runtime-env-unit-custody', release=str(self.release), inputs=inputs,
            scopeMarkerSha256=marker, roles=roles, files={}, activationAuthorized=False, readinessAuthorized=False, updaterOwned=False)
        proof = dict(schemaVersion=1, kind='native-runtime-env-units', status='completed', release=str(self.release), inputs=inputs,
            intentSha256='d' * 64, receiptSha256='d' * 64, files={}, runtimeDeferred=True, activationAuthorized=False, readinessAuthorized=False, updaterOwned=False)
        for role, manifest in roles.items():
            folder = Path('/etc/systemd/system') if role == 'rootful' else Path('/home') / manifest['user'] / '.config/systemd/user'
            for logical, data in ((folder / 'webservices-runtime-env.service', renderer['render_unit'](manifest)),
                                  (folder / 'webservices.target.d/10-runtime-env.conf', renderer['render_dropin']())):
                path = self.physical(logical); self.put(path, data); self.own(path, manifest['uid'], manifest['gid'])
                if logical.name == '10-runtime-env.conf':
                    path.parent.chmod(0o755); self.own(path.parent, manifest['uid'], manifest['gid'])
                info = m.os.stat(path, follow_symlinks=False)
                ids = m.fingerprint(info)  # owning project-domain-runtime.identity order, NOT native-selection.identity
                digest = m.sha(data)
                proof['files'][str(logical)] = dict(dev=info.st_dev, ino=info.st_ino, uid=manifest['uid'], gid=manifest['gid'],
                    mode=0o644, mountId=123, acl='', defaultAcl='', identity=ids, sha256=digest)
                custody['files'][str(logical)] = dict(sha256=digest, uid=manifest['uid'], gid=manifest['gid'], mode=0o644,
                    before=None, stage='.runtime-env-unit-' + 'e' * 32)
        proof['custodySha256'] = m.sha(m.canonical(custody))
        self.receipt_extra.update(nativeRuntimeEnvUnitCustody=custody, nativeRuntimeEnvUnits=proof); self.seal()
        if populated:
            self.receipt_extra['cleanResetCustody'] = m.review_runtime_custody(self.root, self.intent)['cleanResetCustody']; self.seal()
        return custody, proof

    def test_native_env_exact_current_renderer_and_original_fd_proof_clean(self):
        self.native_unit_fixture()
        self.patch(m, 'LEGACY_SOURCE_INSTALLERS', new=frozenset())
        result = self.run_reset(); self.assertTrue(result['completeCleanReset'])
        self.assertTrue(result['rootfulStoreColdAcceptance'])
        self.assertFalse(self.physical(Path('/etc/systemd/system/webservices.target.d')).exists())

    def test_native_env_populated_original_producer_file_seal_and_no_values_in_evidence(self):
        self.native_unit_fixture(populated=True)
        result = self.run_reset(); self.assertTrue(result['completeCleanReset'])
        self.assertEqual(list((self.root / 'runtime-env').iterdir()), [])
        for path in (self.root / '.host-clean-reset').iterdir():
            self.assertNotIn(b'SYNTHETIC_VALUE_DO_NOT_RECORD', path.read_bytes())

    def test_native_env_original_identity_uses_actual_producer_field_order(self):
        import ast
        tree = ast.parse((OPS / 'project-domain-runtime.py').read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'identity')
        namespace = {}; exec(compile(ast.Module(body=[function], type_ignores=[]), '<actual-producer-identity>', 'exec'), namespace)
        with open(self.operator_key, 'rb') as handle:
            self.assertEqual(list(namespace['identity'](m.os.fstat(handle.fileno()))), m.fingerprint(m.os.fstat(handle.fileno())))

    def test_native_env_unknown_present_custody_never_legacy_falls_back(self):
        self.receipt_extra['nativeRuntimeEnvUnitCustody'] = {'kind': 'unknown'}; self.seal(); self.denied()
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_native_env_unapproved_source_or_old_liveops_version_refused(self):
        self.native_unit_fixture()
        name = 'native-runtime-env-units.py'
        with patch.object(m, 'RUNTIME_ENV_RENDERER_PINS', new=dict(m.RUNTIME_ENV_RENDERER_PINS, **{name: frozenset()})): self.denied()
        self.bundle_extra['liveOps']['ops/' + name] = 'f' * 64; self.seal(); self.denied()
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_native_env_unchanged_bytes_new_inode_not_adopted(self):
        self.native_unit_fixture(); path = self.physical(Path('/etc/systemd/system/webservices-runtime-env.service'))
        data = path.read_bytes(); path.rename(path.with_name('retained-authored-original')); self.put(path, data)
        self.denied(); self.assertTrue(path.exists())
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_native_env_wrong_role_marker_uid_namespace_and_mount_refused(self):
        custody, proof = self.native_unit_fixture(); original = copy.deepcopy(custody)
        for key, value in (('uid', 1001), ('runtimeStore', '/run/foreign'), ('scopeMarkerSha256', 'f' * 64)):
            with self.subTest(key=key):
                custody['roles']['rootful'][key] = value
                proof['custodySha256'] = m.sha(m.canonical(custody)); self.seal(); self.denied()
                custody.clear(); custody.update(copy.deepcopy(original))
        proof['custodySha256'] = m.sha(m.canonical(custody)); self.seal()
        with patch.object(m, 'fd_mount_id', return_value=124): self.denied()
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    # Typed NSFS parser models; kernel device proof mocked, no foreign namespace access.
    @contextlib.contextmanager
    def nsfs_views(self, row=None, foreign=False, count=2, kernel_device='0:4'):
        dev = REAL_STAT(self.scope).st_dev; self.mount_device = str(os.major(dev)) + ':' + str(os.minor(dev))
        base = '1 0 ' + self.mount_device + ' / / rw - ext4 /dev/model rw'
        self.nsfs_row = row or '88 1 0:4 net:[4026532720] /run/user/1001/netns/netns-0cffb79e-8d4d-9299-3e6d-bfdd5056122f rw - nsfs nsfs rw'
        views = [[base] for _ in range(count)]
        views[-1 if foreign else 0].append(self.nsfs_row)
        with m.locked(self.root): selection = m.binding(self.root, self.intent)
        with patch.object(m, 'mount_views', return_value=views), \
             patch.object(m, '_mount_nsfs_device', return_value=kernel_device) as kernel:
            yield views, selection['policies'], kernel

    def test_nsfs_actual_unrelated_record_522_views_preserved_without_foreign_path_access(self):
        with self.nsfs_views(count=522) as (views, policies, kernel), patch.object(m, 'directory', wraps=m.directory) as directories:
            for view in views[1:]: view.append(self.nsfs_row)
            m.unmounted([self.scope], policies)
            kernel.assert_called_once_with(); directories.assert_called_once_with(self.scope, policies)
            self.assertTrue(all(self.nsfs_row in view for view in views)); self.assertEqual(len(views), 522)
        self.assertFalse(any(mutate for _, _, mutate in self.cold_calls))

    def test_nsfs_root_label_source_filesystem_device_and_record_shape_are_exact(self):
        original = '88 1 0:4 net:[4026532720] /unrelated/namespace-file rw - nsfs nsfs rw'
        bad = [original.replace('net:[4026532720]', value) for value in
               ('/', 'relative', 'mnt:[4026532720]', 'net:4026532720', 'net:[0]', 'net:[01]', 'net:[18446744073709551616]')]
        bad += [original.replace('nsfs nsfs', 'nsfs other'), original.replace('nsfs nsfs', 'tmpfs nsfs'),
                original.replace('0:4', '0:99'), original + ' extra', original.replace(' - nsfs', ' - - nsfs')]
        for row in bad:
            with self.subTest(row=row), self.nsfs_views(row=row) as (_, policies, kernel), self.assertRaises(m.Refusal):
                m.unmounted([self.scope], policies)

    def test_nsfs_ordinary_bad_roots_remain_invalid_without_namespace_fallback(self):
        for root in ('relative', 'net:[4026532720]', '/tmp/../data', '/bad\x00path'):
            row = '88 1 0:4 ' + root + ' /unrelated/point rw - ext4 /dev/model rw'
            with self.subTest(root=root), self.nsfs_views(row=row) as (_, policies, kernel):
                with self.assertRaises(m.Refusal): m.unmounted([self.scope], policies)
                kernel.assert_not_called()

    def test_nsfs_mountpoint_overlap_refuses_in_current_and_distinct_views(self):
        for foreign in (False, True):
            for point in (self.scope, self.scope / 'namespace-file', self.scope.parent):
                row = '88 1 0:4 net:[4026532720] ' + str(point) + ' rw - nsfs nsfs rw'
                with self.subTest(foreign=foreign, point=point), self.nsfs_views(row=row, foreign=foreign) as (_, policies, _), self.assertRaises(m.Refusal):
                    m.unmounted([self.scope], policies)

    def test_nsfs_unrelated_record_never_hides_an_ordinary_data_alias(self):
        with self.nsfs_views(foreign=True) as (views, policies, _):
            views[-1].append('90 1 ' + self.mount_device + ' ' + str(self.scope) + ' /foreign-alias rw - ext4 /dev/model rw')
            with self.assertRaises(m.Refusal): m.unmounted([self.scope], policies)

    def test_nsfs_cannot_be_selected_data_device_even_with_forged_ordinary_root(self):
        dev = REAL_STAT(self.scope).st_dev; device = str(os.major(dev)) + ':' + str(os.minor(dev))
        row = '88 1 ' + device + ' net:[4026532720] /unrelated/namespace-file rw - nsfs nsfs rw'
        with self.nsfs_views(row=row, kernel_device=device) as (_, policies, _), self.assertRaises(m.Refusal):
            m.unmounted([self.scope], policies)

    def test_nsfs_missing_kernel_device_proof_never_uses_a_label_or_flag_fallback(self):
        with self.nsfs_views() as (_, policies, kernel):
            kernel.side_effect = m.Refusal('kernel namespace unavailable')
            with self.assertRaises(m.Refusal): m.unmounted([self.scope], policies)

    def test_nsfs_mountpoints_remain_strict_filesystem_paths(self):
        for point in ('relative', '/tmp/../namespace-file', '/bad\x00point', '/'):
            row = '88 1 0:4 net:[4026532720] ' + point + ' rw - nsfs nsfs rw'
            with self.subTest(point=point), self.nsfs_views(row=row) as (_, policies, _), self.assertRaises(m.Refusal):
                m.unmounted([self.scope], policies)


class MountViews(unittest.TestCase):
    """Real isolated FDs/PID files; procfs/nsfs kernel type is explicitly modeled.

    No host /proc/process query. Genuine fstatfs negative case uses temp files.
    """
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='reset-mount-fd-'); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name); self.proc = self.base / 'proc'; self.proc.mkdir()
        self.root = self.base / 'root'; self.root.mkdir(); (self.root / 'data').mkdir()
        self.chroot = self.base / 'avahi-root'; self.chroot.mkdir()
        self.ns = self.base / 'ns-current'; self.ns.write_bytes(b'mnt:[same-text-is-not-authority]')
        self.foreign = self.base / 'ns-foreign'; self.foreign.write_bytes(self.ns.read_bytes())
        self.pid = os.getpid(); self.peer = self.pid + 1
        dev = REAL_STAT(self.root).st_dev; self.device = str(os.major(dev)) + ':' + str(os.minor(dev))
        self.full = '1 0 ' + self.device + ' / / rw - ext4 /dev/model rw\n'
        for pid in (self.pid, self.peer):
            parent = self.proc / str(pid); parent.mkdir(); (parent / 'ns').mkdir()
            (parent / 'stat').write_bytes((str(pid) + ' (isolated fixture) S ' + '0 ' * 18 + '555\n').encode())
            (parent / 'mountinfo').write_text(self.full if pid == self.pid else '')
            (parent / 'ns/mnt').symlink_to(self.ns)
            (parent / 'root').symlink_to(self.root if pid == self.pid else self.chroot)
        (self.proc / 'self').symlink_to(str(self.pid))
        self.hook = None

    @contextlib.contextmanager
    def kernel_model(self):
        real_close, real_read = os.close, m._mount_proc_read
        proc_keys = {(REAL_STAT(path).st_dev, REAL_STAT(path).st_ino) for path in [self.proc, *self.proc.rglob('*')]
                     if not path.is_symlink()}
        ns_keys = {(REAL_STAT(path).st_dev, REAL_STAT(path).st_ino) for path in (self.ns, self.foreign)}
        opened = set()
        def mapping(path):
            return str(self.proc) if path == '/proc' else str(self.root) if path == '/' else path
        def opening(path, *args, **kwargs):
            fd = REAL_OPEN(mapping(path), *args, **kwargs); opened.add(fd); return fd
        def closing(fd): opened.discard(fd); real_close(fd)
        def kernel(fd, namespace=False):
            info = REAL_FSTAT(fd)
            m.require((info.st_dev, info.st_ino) in (ns_keys if namespace else proc_keys), 'Modeled kernel filesystem type differs')
        def reading(parent, leaf):
            data = real_read(parent, leaf)
            if self.hook is not None: self.hook(parent, leaf, data)
            return data
        with patch.object(m.os, 'open', new=opening), patch.object(m.os, 'close', new=closing), \
             patch.object(m.os, 'stat', new=lambda path, *a, **kw: REAL_STAT(mapping(path), *a, **kw)), \
             patch.object(m, '_mount_kernel_fs', new=kernel), patch.object(m, '_mount_proc_read', new=reading):
            try: yield
            finally: self.assertFalse(opened, 'Mount observation leaked held descriptors')

    def on_peer_mount_read(self, action):
        peer_inode = REAL_STAT(self.proc / str(self.peer)).st_ino
        def hook(fd, leaf, data):
            if leaf == 'mountinfo' and REAL_FSTAT(fd).st_ino == peer_inode:
                self.hook = None; action()
        self.hook = hook

    def test_same_held_namespace_empty_chroot_uses_complete_stable_self_view(self):
        @contextlib.contextmanager
        def directory(path, policies=None):
            fd = REAL_OPEN(path, os.O_RDONLY | os.O_DIRECTORY)
            try: yield fd
            finally: os.close(fd)
        with self.kernel_model():
            views = m.mount_views()
            self.assertEqual(len(views), 3)
            self.assertTrue(all(view == self.full.splitlines() for view in views))
            with patch.object(m, 'directory', new=directory): m.unmounted([self.root / 'data'])
        self.assertEqual((self.proc / str(self.peer) / 'mountinfo').read_bytes(), b'')

    def test_empty_foreign_namespace_or_nonchroot_refuses_despite_identical_ns_text(self):
        link = self.proc / str(self.peer) / 'ns/mnt'; link.unlink(); link.symlink_to(self.foreign)
        with self.kernel_model(), self.assertRaises(m.Refusal): m.mount_views()
        link.unlink(); link.symlink_to(self.ns)
        root = self.proc / str(self.peer) / 'root'; root.unlink(); root.symlink_to(self.root)
        with self.kernel_model(), self.assertRaises(m.Refusal): m.mount_views()

    def test_distinct_nonempty_namespace_retained_and_alias_refused(self):
        link = self.proc / str(self.peer) / 'ns/mnt'; link.unlink(); link.symlink_to(self.foreign)
        alias = '2 1 ' + self.device + ' ' + str(self.root / 'data') + ' /elsewhere rw - ext4 /dev/model rw'
        (self.proc / str(self.peer) / 'mountinfo').write_text(self.full + alias + '\n')
        with self.kernel_model(): views = m.mount_views()
        self.assertTrue(any(alias in view for view in views))
        @contextlib.contextmanager
        def directory(path, policies=None):
            fd = REAL_OPEN(path, os.O_RDONLY | os.O_DIRECTORY)
            try: yield fd
            finally: os.close(fd)
        with patch.object(m, 'mount_views', return_value=views), patch.object(m, 'directory', new=directory), self.assertRaises(m.Refusal):
            m.unmounted([self.root / 'data'])

    def test_original_pid_starttime_change_refuses(self):
        path = self.proc / str(self.peer) / 'stat'
        self.on_peer_mount_read(lambda: path.write_bytes(path.read_bytes().replace(b'555', b'556')))
        with self.kernel_model(), self.assertRaises(m.Refusal): m.mount_views()

    def test_original_named_proc_inode_replacement_refuses(self):
        def replace():
            old = self.proc / str(self.peer); old.rename(self.proc / 'retained-original')
            old.mkdir()
        self.on_peer_mount_read(replace)
        with self.kernel_model(), self.assertRaises(m.Refusal): m.mount_views()

    def test_original_namespace_changes_refuse_for_process_and_self(self):
        for pid in (self.peer, self.pid):
            link = self.proc / str(pid) / 'ns/mnt'
            def replace(): link.unlink(); link.symlink_to(self.foreign)
            self.on_peer_mount_read(replace)
            with self.subTest(pid=pid), self.kernel_model(), self.assertRaises(m.Refusal): m.mount_views()
            link.unlink(); link.symlink_to(self.ns)

    def test_original_chroot_root_fd_change_refuses(self):
        link = self.proc / str(self.peer) / 'root'
        def replace(): link.unlink(); link.symlink_to(self.root)
        self.on_peer_mount_read(replace)
        with self.kernel_model(), self.assertRaises(m.Refusal): m.mount_views()

    def test_same_namespace_mount_table_change_refuses_without_inode_change(self):
        path = self.proc / str(self.pid) / 'mountinfo'
        self.on_peer_mount_read(lambda: path.write_text(self.full + '2 1 ' + self.device + ' /hidden /alias rw - ext4 /dev/model rw\n'))
        with self.kernel_model(), self.assertRaises(m.Refusal): m.mount_views()

    def test_original_peer_mount_table_change_refuses(self):
        path = self.proc / str(self.peer) / 'mountinfo'
        self.on_peer_mount_read(lambda: path.write_text(self.full))
        with self.kernel_model(), self.assertRaises(m.Refusal): m.mount_views()

    def test_incomplete_self_view_and_wrong_original_proc_kernel_type_refuse(self):
        path = self.proc / str(self.pid) / 'mountinfo'; path.write_bytes(b'')
        with self.kernel_model(), self.assertRaises(m.Refusal): m.mount_views()
        path.write_text(self.full.replace(' / / ', ' /unproven-chroot / '))
        with self.kernel_model(), self.assertRaises(m.Refusal): m.mount_views()
        path.write_text(self.full)
        with self.kernel_model(), patch.object(m, '_mount_kernel_fs', side_effect=m.Refusal('not kernel procfs')), self.assertRaises(m.Refusal):
            m.mount_views()

    def test_nsfs_device_is_observed_from_our_held_kernel_namespace_fd(self):
        with self.kernel_model():
            self.assertEqual(m._mount_nsfs_device(), self.device)

    def test_unknown_empty_namespace_is_not_skipped_or_inferred_from_symlink_text(self):
        (self.proc / str(self.peer) / 'ns/mnt').unlink()
        with self.kernel_model(), self.assertRaises(m.Refusal): m.mount_views()

    def test_kernel_nsfs_requires_mount_namespace_ioctl_type_not_just_inode(self):
        fd = REAL_OPEN(self.ns, os.O_RDONLY)
        def nsfs(fd, data):
            m.ctypes.c_long.from_buffer(data).value = 0x6e736673
            return 0
        try:
            with patch.object(m.ctypes, 'CDLL', return_value=types.SimpleNamespace(fstatfs=nsfs)), \
                 patch.object(m.fcntl, 'ioctl', return_value=0) as ioctl:
                with self.assertRaises(m.Refusal): m._mount_kernel_fs(fd, namespace=True)
                ioctl.return_value = 0x00020000
                m._mount_kernel_fs(fd, namespace=True)
                self.assertEqual(ioctl.call_args.args, (fd, 0xb703))
        finally: os.close(fd)

    def test_real_temp_fd_cannot_impersonate_kernel_procfs_or_nsfs(self):
        fd = REAL_OPEN(self.ns, os.O_RDONLY)
        try:
            for namespace in (False, True):
                with self.subTest(namespace=namespace), self.assertRaises(m.Refusal): m._mount_kernel_fs(fd, namespace=namespace)
        finally: os.close(fd)


if __name__ == '__main__':
    unittest.main(verbosity=2)
