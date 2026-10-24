#!/usr/bin/env python3
"""Synthetic, temp-root-only domain projection contracts; no native installer."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).absolute().parents[1] / 'runtime-generator/podman-ops/project-domain-runtime.py'
SPEC = importlib.util.spec_from_file_location('domain_projection', SOURCE)
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)


class Projection(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='domain-projection-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.scope = self.base / 'scope'
        self.install = self.scope / 'installer'
        self.release = self.install / 'releases/r1'
        self.state = self.scope / 'actor-state'
        self.slot = self.state / 'releases/r1'
        self.destination = self.slot / 'runtime'
        self.config = self.release / 'runtime/configs'
        self.user = 'webservices-test-runners'
        self.uid = 24001
        self.row = {'name': 'test-runners', 'user': self.user, 'uid': self.uid,
                    'stateRoot': str(self.state), 'graphRoot': str(self.scope / 'actor-graph'),
                    'volumeRoot': str(self.scope / 'actor-volumes'),
                    'services': ['app', 'test-runner']}
        self.scope_config = {'root': str(self.scope), 'dataClass': 'synthetic'}
        self.manifest = {'site': 'synthetic.invalid', 'deploymentMode': 'standalone',
                         'storageScope': self.scope_config}
        self.metadata = {'schemaVersion': 1, 'deploymentMode': 'standalone',
                         'installerStateRoot': str(self.install), 'storageScope': self.scope_config,
                         'domains': [self.row]}
        self.ir = {'services': {
            'app': {'placement': 'rootless', 'rootlessDomain': 'test-runners',
                    'environment': {'API_TOKEN': '${APP_TOKEN}', 'ENABLED': True,
                                    'URL': '${URL:-https://${DOMAIN}}'},
                    'volumes': ['./configs/shared/public.json:/config/public.json:ro',
                                {'type': 'bind', 'source': './configs/app/subtree', 'target': '/config/app'}]},
            'test-runner': {'placement': 'rootless', 'rootlessDomain': 'test-runners',
                            'environment': {'DOMAIN': '${DOMAIN}'}, 'volumes': []},
            'unrelated': {'placement': 'rootless', 'rootlessDomain': 'other',
                          'environment': {'PASSWORD': '${UNRELATED_SECRET}'},
                          'volumes': ['./configs/shared/private.env:/config/private.env']}}}
        self.put(self.release / 'bundle.json', '{}\n')
        self.put(self.release / 'source-provenance.json', '{}\n')
        self.put(self.release / 'runtime/stack.env',
                 'DOMAIN=synthetic.invalid\nAPP_TOKEN=selected-test-token\n'
                 'UNRELATED_SECRET=UNRELATED_SECRET_SENTINEL\n'
                 'P0_DERIVATION_MASTER_KEY=ROOT_ONLY_MASTER_SENTINEL\n')
        self.put(self.config / 'shared/public.json', '{"synthetic":true}\n')
        self.put(self.config / 'shared/private.env', 'UNRELATED_SECRET_SENTINEL\n')
        self.put(self.config / 'app/subtree/script.sh', '#!/bin/sh\nexit 0\n')
        self.put(self.config / 'app/subtree/nested/a.txt', 'declared subtree\n')
        self.mkdir(self.config / 'app/subtree/empty')
        self.put(self.config / 'app/unmounted.txt', 'UNMOUNTED_PARENT_SENTINEL\n')
        # Untrusted templates must never grant env authority, even to the runner.
        self.put(self.release / 'runtime-env/test-runner.env.template',
                 'UNRELATED_SECRET=${UNRELATED_SECRET}\nMASTER=${P0_DERIVATION_MASTER_KEY}\n')
        self.mkdir(self.slot)
        self.previous = self.state / 'releases/previous/runtime/old.txt'
        self.put(self.previous, 'previous private runtime stays unchanged\n')
        self.reseal()
        self.addCleanup(patch.stopall)
        patch.object(p, 'OWNER', os.getuid()).start()
        patch.object(p.os, 'geteuid', return_value=0).start()
        # /tmp and developer-owned ancestors cannot be root-controlled in a
        # nonprivileged fixture. Check every ancestor INSIDE this isolated root;
        # production trusted_chain is separately tested and is never bypassable
        # by a CLI flag/environment variable.
        def fixture_chain(path):
            if not path.is_relative_to(self.base):
                raise p.Refusal('test attempted external access')
            for node in (*reversed(path.parents), path):
                if node == self.base or node.is_relative_to(self.base):
                    p.controlled(node.lstat(), directory=True)
        self.real_chain = p.trusted_chain
        patch.object(p, 'trusted_chain', side_effect=fixture_chain).start()

    def mkdir(self, path):
        if path.exists():
            return
        self.mkdir(path.parent)
        path.mkdir(mode=0o700)

    def put(self, path, body):
        self.mkdir(path.parent)
        path.write_bytes(body.encode() if isinstance(body, str) else body)
        path.chmod(0o600)

    def reseal(self):
        for name, value in [('stack.ir.json', self.ir), ('podman-domains.json', self.metadata),
                            ('site/manifest.json', self.manifest)]:
            self.put(self.release / name, p.encoded(value))
        self.marker = {'schemaVersion': 1, 'kind': 'standalone-stack-storage',
                       'site': self.manifest['site'], 'scope': self.scope_config,
                       'domains': [{key: self.row[key] for key in
                                    ('name', 'user', 'uid', 'stateRoot', 'graphRoot', 'volumeRoot')}],
                       'roots': sorted(self.row[key] for key in ('stateRoot', 'graphRoot', 'volumeRoot'))}
        self.put(self.scope / '.stack-installation.json', p.encoded(self.marker))
        self.receipt = {'schemaVersion': 1, 'phase': 'preparing', 'release': str(self.release),
                        'inputs': {name: p.sha((self.release / name).read_bytes()) for name in p.REQUIRED},
                        'previousRelease': None, 'steps': ['preparing']}
        self.save_receipt()

    def save_receipt(self):
        self.put(self.release / 'installation-receipt.json', p.encoded(self.receipt))
        self.put(self.install / '.install-intent.json', p.encoded(self.receipt))
        self.intent_sha = p.sha((self.install / '.install-intent.json').read_bytes())
        self.marker_sha = p.sha((self.scope / '.stack-installation.json').read_bytes())

    def args(self):
        return dict(release=self.release, destination=self.destination, domain='test-runners',
                    user=self.user, uid=self.uid, state_root=self.state,
                    expected_install_intent_sha256=self.intent_sha,
                    expected_scope_marker_sha256=self.marker_sha)

    def project(self, **changes):
        return p.project(**(self.args() | changes))

    def refuse(self, **changes):
        before = self.previous.read_bytes()
        with self.assertRaises((ValueError, OSError, KeyError, TypeError)):
            self.project(**changes)
        self.assertFalse(self.destination.exists())
        self.assertEqual(self.previous.read_bytes(), before)

    def empty_domain(self):
        self.ir['services'] = {key: value for key, value in self.ir['services'].items()
                               if value.get('rootlessDomain') != self.row['name']}
        self.row['services'] = []
        self.reseal()

    def test_empty_domain_has_no_runtime_source_authority(self):
        self.empty_domain()
        (self.release / 'runtime').rename(self.release / 'unread-runtime')
        with patch.object(p, 'subtree', side_effect=AssertionError('empty domain opened runtime')), \
                patch.object(p, 'owner_import_material', side_effect=AssertionError('empty domain queried realm')), \
                patch.object(p, 'env_values', side_effect=AssertionError('empty domain parsed env')), \
                patch.object(p, 'root_only', side_effect=AssertionError('empty domain queried master keys')):
            proof = self.project()
        self.assertEqual(proof['files'], {})
        self.assertIsNone(proof['aggregateSha256'])
        self.assertEqual(proof['services'], [])
        self.assertEqual(proof['configMounts'], [])
        self.assertEqual(proof['environmentInputs'], [])
        self.assertEqual(proof['directories'], ['configs', 'service-env'])
        self.assertEqual(set(x.name for x in self.destination.iterdir()), {'configs', 'service-env', 'projection.json'})
        self.assertNotIn('aggregateSha256', p.strict((self.destination / 'projection.json').read_bytes()))

    def test_empty_domain_unselected_secret_changes_are_not_queried(self):
        self.empty_domain()
        original = p.write_file
        def mutate(*args, **kwargs):
            original(*args, **kwargs)
            self.put(self.release / 'runtime/stack.env', 'not even valid env')
            self.put(self.config / p.IDP_REALM, 'not even valid JSON')
        with patch.object(p, 'write_file', side_effect=mutate):
            proof = self.project()
        self.assertEqual(proof['files'], {})

    def test_empty_domain_still_requires_exact_selected_identity(self):
        self.empty_domain()
        self.refuse(uid=self.uid + 1)
        self.refuse(user='foreign-actor')
        self.refuse(domain='other')

    def test_empty_domain_still_requires_exact_selected_services(self):
        self.empty_domain(); self.row['services'] = ['missing']; self.reseal()
        self.refuse()

    def test_empty_domain_still_rechecks_marker_and_cas(self):
        self.empty_domain()
        original = p.write_file
        def mutate(*args, **kwargs):
            original(*args, **kwargs)
            self.put(self.scope / '.stack-installation.json', '{}\n')
        with patch.object(p, 'write_file', side_effect=mutate):
            self.refuse()

    def test_exact_files_and_declared_subtree_not_top_level_parents(self):
        proof = self.project()
        expected = {'configs/shared/public.json', 'configs/app/subtree/script.sh',
                    'configs/app/subtree/nested/a.txt', 'service-env/app.env',
                    'service-env/test-runner.env', 'projection.json'}
        actual = {str(x.relative_to(self.destination)) for x in self.destination.rglob('*') if x.is_file()}
        self.assertEqual(actual, expected)
        self.assertTrue((self.destination / 'configs/app/subtree/empty').is_dir())
        self.assertFalse(proof['activationAuthorized'])
        for node in (self.destination, *self.destination.rglob('*')):
            mode = 0o700 if node.is_dir() or node.name == 'script.sh' else 0o600
            self.assertEqual(stat.S_IMODE(node.stat().st_mode), mode)
            self.assertEqual(node.stat().st_uid, os.getuid())
        for key, digest in proof['files'].items():
            self.assertEqual(p.sha((self.destination / key).read_bytes()), digest)
        self.assertEqual(proof['projectionSha256'], p.sha((self.destination / 'projection.json').read_bytes()))
        self.assertEqual((self.destination / 'service-env/app.env').read_text(),
                         'API_TOKEN=selected-test-token\nENABLED=true\nURL=https://synthetic.invalid\n')

    def test_runner_has_no_aggregate_or_undeclared_secret(self):
        self.project()
        self.assertFalse((self.destination / 'stack.env').exists())
        self.assertEqual((self.destination / 'service-env/test-runner.env').read_text(), 'DOMAIN=synthetic.invalid\n')
        for node in self.destination.rglob('*'):
            if node.is_file():
                for sentinel in (b'UNRELATED_SECRET_SENTINEL', b'ROOT_ONLY_MASTER_SENTINEL', b'UNMOUNTED_PARENT_SENTINEL'):
                    self.assertNotIn(sentinel, node.read_bytes())

    def test_unmounted_sibling_link_not_followed_or_copied(self):
        (self.config / 'shared/unmounted-link').symlink_to('/external-not-readable')
        self.project()
        self.assertFalse(os.path.lexists(self.destination / 'configs/shared/unmounted-link'))

    def test_wrong_selection_and_hashes(self):
        for change in ({'domain': 'other'}, {'user': 'other-user'}, {'uid': self.uid + 1},
                       {'state_root': self.scope / 'other'},
                       {'destination': self.scope / 'outside/runtime'},
                       {'expected_install_intent_sha256': '0' * 64},
                       {'expected_scope_marker_sha256': '0' * 64}):
            with self.subTest(change=change):
                self.refuse(**change)

    def test_receipt_must_match_intent(self):
        self.receipt['previousRelease'] = 'foreign'
        self.put(self.release / 'installation-receipt.json', p.encoded(self.receipt))
        self.refuse()

    def test_nonpreparing_phase(self):
        self.receipt['phase'] = 'active'
        self.save_receipt()
        self.refuse()

    def test_changed_hashed_ir(self):
        self.put(self.release / 'stack.ir.json', '{}\n')
        self.refuse()

    def test_pinned_absence_enforced(self):
        self.receipt['inputs']['site/components.lock.json'] = None
        self.save_receipt()
        self.put(self.release / 'site/components.lock.json', '{}\n')
        self.refuse()

    def test_foreign_scope_marker_even_with_new_hash(self):
        self.marker['domains'][0]['uid'] += 1
        self.put(self.scope / '.stack-installation.json', p.encoded(self.marker))
        self.marker_sha = p.sha((self.scope / '.stack-installation.json').read_bytes())
        self.refuse()

    def test_metadata_services_must_equal_selected_ir(self):
        self.row['services'].append('unrelated')
        self.reseal()
        self.refuse()

    def test_overlapping_storage_roots(self):
        self.row['graphRoot'] = str(self.state / 'nested-graph')
        self.reseal()
        self.refuse()

    def test_duplicate_json_key_rejected(self):
        self.put(self.release / 'stack.ir.json', '{"services":{},"services":{}}')
        self.receipt['inputs']['stack.ir.json'] = p.sha((self.release / 'stack.ir.json').read_bytes())
        self.save_receipt()
        self.refuse()

    def test_selected_file_symlink(self):
        selected = self.config / 'shared/public.json'
        selected.unlink()
        selected.symlink_to('private.env')
        self.refuse()

    def test_selected_intermediate_symlink(self):
        shared = self.config / 'shared'
        shared.rename(self.config / 'moved')
        shared.symlink_to('moved', target_is_directory=True)
        self.refuse()

    def test_selected_subtree_symlink(self):
        (self.config / 'app/subtree/link').symlink_to('../../shared/private.env')
        self.refuse()

    def test_selected_hardlink(self):
        source = self.config / 'shared/public.json'
        os.link(source, self.config / 'shared/second-link')
        self.refuse()

    def test_aggregate_hardlink(self):
        os.link(self.release / 'runtime/stack.env', self.release / 'runtime/second.env')
        self.refuse()

    def test_selected_fifo(self):
        source = self.config / 'shared/public.json'
        source.unlink()
        os.mkfifo(source, 0o600)
        self.refuse()

    def test_traversal_and_aggregate_mounts(self):
        for source in ('./configs/../stack.env', './configs//shared/public.json',
                       './configs/shared/./public.json', '/alias/configs/shared/public.json',
                       './runtime/stack.env', './configs', 'configs/shared/public.json'):
            with self.subTest(source=source):
                self.ir['services']['app']['volumes'] = [source + ':/mounted:ro']
                self.reseal()
                self.refuse()

    def test_missing_declared_mount_fails_closed(self):
        (self.config / 'shared/public.json').unlink()
        self.refuse()

    def test_root_only_key_reference_or_alias_rejected(self):
        for key, value in [('MASTER', '${P0_DERIVATION_MASTER_KEY}'),
                           ('ROOT_ONLY_KEY', 'otherwise safe'),
                           ('ALIAS', 'ROOT_ONLY_MASTER_SENTINEL')]:
            with self.subTest(key=key):
                self.ir['services']['test-runner']['environment'] = {key: value}
                self.reseal()
                self.refuse()

    def test_module_derivation_salt_is_not_root_master(self):
        self.ir['services']['app']['environment']['MASTODON_ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT'] = 'synthetic-module-salt'
        self.reseal()
        self.project()
        self.assertIn('MASTODON_ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT=synthetic-module-salt\n',
                      (self.destination / 'service-env/app.env').read_text())

    def test_nonbind_config_mount_rejected(self):
        self.ir['services']['app']['volumes'] = [{'type': 'volume', 'source': './configs/shared/public.json', 'target': '/config'}]
        self.reseal()
        self.refuse()

    def test_redundant_nested_mount_retains_only_selected_subtree(self):
        self.ir['services']['app']['volumes'].append('./configs/app/subtree/nested/a.txt:/also-mounted')
        self.reseal()
        proof = self.project()
        self.assertIn('configs/app/subtree/empty', proof['directories'])
        self.assertFalse((self.destination / 'configs/app/unmounted.txt').exists())

    def test_root_only_material_in_config_rejected(self):
        self.put(self.config / 'shared/public.json', 'ROOT_ONLY_MASTER_SENTINEL')
        self.refuse()

    def test_custom_root_only_key(self):
        aggregate = self.release / 'runtime/stack.env'
        self.put(aggregate, aggregate.read_bytes() + b'CUSTOM_MASTER=custom-synthetic-master\n')
        self.ir['services']['app']['environment']['ALIAS'] = '${CUSTOM_MASTER}'
        self.reseal()
        self.refuse(root_only_env_keys=['CUSTOM_MASTER'])

    def test_health_inputs_exact_and_nested_defaults(self):
        self.ir['services']['app']['health'] = {'test': ['CMD-SHELL', 'test -n "$APP_TOKEN" && echo $$IGNORED']}
        self.reseal()
        proof = self.project()
        self.assertEqual(proof['environmentInputs'], ['APP_TOKEN', 'DOMAIN', 'URL'])
        self.assertIn('P0_HEALTH_INPUT_APP_TOKEN=selected-test-token\n',
                      (self.destination / 'service-env/app.env').read_text())
        self.assertNotIn('IGNORED', (self.destination / 'service-env/app.env').read_text())

    def test_inserted_secret_not_interpreted_as_template(self):
        aggregate = self.release / 'runtime/stack.env'
        self.put(aggregate, aggregate.read_bytes().replace(b'APP_TOKEN=selected-test-token',
                                                         b'APP_TOKEN=${UNRELATED_SECRET}'))
        self.project()
        self.assertIn('API_TOKEN=${UNRELATED_SECRET}', (self.destination / 'service-env/app.env').read_text())

    def test_unresolved_missing_or_multiline_input_fails_closed(self):
        for template in ('${MISSING}', '${MISSING:?message}', '${UNCLOSED', '${APP_TOKEN:+other}', 'literal\rdata'):
            with self.subTest(template=template):
                self.ir['services']['app']['environment']['NEGATIVE'] = template
                self.reseal()
                self.refuse()

    def test_existing_destination_retained_even_empty(self):
        self.mkdir(self.destination)
        with self.assertRaises((p.Refusal, OSError)):
            self.project()
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_existing_populated_projection_is_never_replaced(self):
        self.project()
        before = {str(node.relative_to(self.destination)): node.read_bytes()
                  for node in self.destination.rglob('*') if node.is_file()}
        with self.assertRaises(p.Refusal):
            self.project()
        after = {str(node.relative_to(self.destination)): node.read_bytes()
                 for node in self.destination.rglob('*') if node.is_file()}
        self.assertEqual(before, after)

    def test_existing_symlink_destination_not_followed(self):
        self.destination.symlink_to(self.previous.parent, target_is_directory=True)
        with self.assertRaises((p.Refusal, OSError)):
            self.project()
        self.assertTrue(self.destination.is_symlink())
        self.assertEqual(self.previous.read_text(), 'previous private runtime stays unchanged\n')

    def test_failed_write_leaves_no_published_destination(self):
        original = p.write_file
        def fail(root, name, body, executable=False):
            original(root, name, body, executable)
            raise OSError('synthetic disk interruption')
        with patch.object(p, 'write_file', side_effect=fail):
            self.refuse()
        private = list(self.slot.glob('.domain-projection-*'))
        self.assertEqual(len(private), 1)
        self.assertEqual(stat.S_IMODE(private[0].stat().st_mode), 0o700)

    def test_interruption_before_publish_retains_previous(self):
        with patch.object(p, 'publish', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.project()
        self.assertFalse(self.destination.exists())
        self.assertEqual(self.previous.read_text(), 'previous private runtime stays unchanged\n')

    def test_config_changed_during_stage_refused(self):
        original = p.write_file
        def mutate(*args, **kwargs):
            original(*args, **kwargs)
            self.put(self.config / 'shared/public.json', 'changed selected config\n')
        with patch.object(p, 'write_file', side_effect=mutate):
            self.refuse()

    def test_intent_cas_changed_during_stage_refused(self):
        original = p.write_file
        def mutate(*args, **kwargs):
            original(*args, **kwargs)
            self.put(self.install / '.install-intent.json', '{}\n')
        with patch.object(p, 'write_file', side_effect=mutate):
            self.refuse()

    def test_destination_race_noreplace(self):
        original = p.publish
        def race(parent, stage, destination):
            self.put(self.destination / 'foreign.txt', 'do not replace\n')
            original(parent, stage, destination)
        with patch.object(p, 'publish', side_effect=race):
            with self.assertRaises(OSError):
                self.project()
        self.assertEqual((self.destination / 'foreign.txt').read_text(), 'do not replace\n')

    def test_root_ownership_and_private_stage_enforced(self):
        with patch.object(p, 'OWNER', os.getuid() + 1):
            self.refuse()
        self.slot.chmod(0o755)
        self.refuse()

    def test_actor_writable_ancestor_rejected(self):
        self.state.chmod(0o777)
        self.refuse()

    def test_no_symlink_in_absolute_ancestor_walk(self):
        alias = self.base / 'release-alias'
        alias.symlink_to(self.release, target_is_directory=True)
        with self.assertRaises(OSError):
            with p.directory(alias / 'runtime'):
                self.fail('linked ancestor accepted')

    def test_production_chain_rejects_nonroot_ownership_or_writability(self):
        self.state.chmod(0o777)
        with self.assertRaises(p.Refusal):
            self.real_chain(self.state)

    def test_nonroot_entry_refused(self):
        with patch.object(p.os, 'geteuid', return_value=1000):
            self.refuse()

    def test_openat2_nofollow_and_beneath(self):
        with p.directory(self.config) as fd:
            for name in ('../stack.env', '/etc/passwd'):
                with self.subTest(name=name), self.assertRaises(OSError):
                    child = p.child_open(fd, name, os.O_RDONLY)
                    os.close(child)


class CustodyProjection(unittest.TestCase):
    # Reuse only the isolated fixture builders, not duplicate inherited tests.
    mkdir = Projection.mkdir
    put = Projection.put
    reseal = Projection.reseal
    save_receipt = Projection.save_receipt
    args = Projection.args
    refuse = Projection.refuse
    empty_domain = Projection.empty_domain

    def setUp(self):
        Projection.setUp(self)
        old_install = self.install
        self.install = self.base / 'sealed-install'
        old_install.rename(self.install)
        self.release = self.install / 'releases/r1'
        self.config = self.release / 'runtime/configs'
        self.metadata['installerStateRoot'] = str(self.install)
        self.operator = os.getuid() + 10001
        self.operator_gid = os.getgid() + 10001
        self.actor_gid = self.uid
        self.mkdir(Path(self.row['graphRoot']))
        self.mkdir(Path(self.row['volumeRoot']))
        self.scope.chmod(0o2770)
        self.reseal()
        # No privileged chown/setfacl/mount operations. Model exact inode-bound
        # ownership and Linux ACL bytes only inside this test's disposable root.
        self.virtual = {}
        for node, uid, gid in [(self.scope, self.operator, self.operator_gid),
                               (self.state, self.uid, self.actor_gid),
                               (self.state / 'releases', self.uid, self.actor_gid),
                               (Path(self.row['graphRoot']), self.uid, self.actor_gid),
                               (Path(self.row['volumeRoot']), self.uid, self.actor_gid),
                               (self.slot, p.OWNER, p.OWNER)]:
            s = node.stat()
            self.virtual[s.st_dev, s.st_ino] = uid, gid
        original_fstat = p.os.fstat
        class VirtualStat:
            def __init__(inner, actual):
                inner.actual = actual
                inner.st_uid, inner.st_gid = self.virtual.get((actual.st_dev, actual.st_ino),
                                                              (actual.st_uid, actual.st_gid))
            def __getattr__(inner, name):
                return getattr(inner.actual, name)
        patch.object(p.os, 'fstat', side_effect=lambda fd: VirtualStat(original_fstat(fd))).start()
        self.scope_acl = self.acl([(1, 7, 0xffffffff), (2, 1, self.uid),
                                   (4, 7, 0xffffffff), (16, 7, 0xffffffff), (32, 0, 0xffffffff)])
        original_acl = p.acl_bytes
        scope_identity = (self.scope.stat().st_dev, self.scope.stat().st_ino)
        def fixture_acl(fd, name):
            s = original_fstat(fd)
            if (s.st_dev, s.st_ino) == scope_identity and name == 'system.posix_acl_access':
                return self.scope_acl
            return original_acl(fd, name)
        patch.object(p, 'acl_bytes', side_effect=fixture_acl).start()
        self.lease = self.Lease()
        self.seal_custody()

    @staticmethod
    def acl(rows):
        return struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *row) for row in rows)

    class Lease:
        def __init__(self):
            self.calls = []
            self.valid = True
        def verify_projection(self, selection):
            self.calls.append(selection)
            if not self.valid:
                raise p.Refusal('synthetic canonical lease lost')

    def record(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            return p.custody_record(fd)
        finally:
            os.close(fd)

    def seal_custody(self):
        paths = {self.scope, self.state, self.state / 'releases', self.slot,
                 Path(self.row['graphRoot']), Path(self.row['volumeRoot'])}
        for node in tuple(paths):
            while node != self.scope:
                paths.add(node)
                node = node.parent
                if not node.is_relative_to(self.scope):
                    raise AssertionError('fixture escaped selected scope')
        state_fd = os.open(self.state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            current = p.current_record(state_fd)
        finally:
            os.close(state_fd)
        self.receipt['projectionCustody'] = {
            'schemaVersion': 1,
            'selection': {'release': str(self.release), 'destination': str(self.destination),
                          'domain': 'test-runners', 'user': self.user, 'uid': self.uid,
                          'scopeMarkerSha256': self.marker_sha},
            'operatorUid': self.operator, 'operatorGid': self.operator_gid, 'actorGid': self.actor_gid,
            'directories': {str(node): self.record(node) for node in paths}, 'current': current}
        self.save_receipt()

    def project(self, **changes):
        return p.project(**(self.args() | {'custody_lease': self.lease} | changes))

    def test_actual_model_scope_and_actor_roots(self):
        proof = self.project()
        self.assertFalse(proof['activationAuthorized'])
        self.assertGreater(len(self.lease.calls), 3)
        for selected in self.lease.calls:
            self.assertEqual(selected['uid'], self.uid)
            self.assertEqual(selected['intentSha256'], self.intent_sha)
            self.assertEqual(selected['receiptSha256'], self.intent_sha)
        self.assertEqual(stat.S_IMODE(self.scope.stat().st_mode), 0o2770)
        self.assertEqual((self.destination / 'service-env/test-runner.env').read_text(),
                         'DOMAIN=synthetic.invalid\n')
        self.assertFalse((self.destination / 'stack.env').exists())

    def test_empty_domain_custody_still_checks_lease_and_receipt(self):
        self.empty_domain(); self.seal_custody()
        self.mutate_during_stage(lambda: setattr(self.lease, 'valid', False))

    def root_volume_parent(self, *, named_uid=None, permission=6, mask=5):
        parent = self.scope / 'volumes'
        self.mkdir(parent); parent.chmod(0o755)
        s = parent.stat()
        self.virtual[s.st_dev, s.st_ino] = p.OWNER, self.operator_gid
        volume = parent / 'selected'
        Path(self.row['volumeRoot']).rename(volume)
        self.row['volumeRoot'] = str(volume)
        access = self.acl([(1, 7, 0xffffffff),
                           (2, permission, self.operator if named_uid is None else named_uid),
                           (4, 5, 0xffffffff), (16, mask, 0xffffffff), (32, 5, 0xffffffff)])
        original = p.acl_bytes
        def fixture_acl(fd, name):
            seen = os.fstat(fd)
            if (seen.st_dev, seen.st_ino) == (s.st_dev, s.st_ino) and name == 'system.posix_acl_access':
                return access
            return original(fd, name)
        patch.object(p, 'acl_bytes', side_effect=fixture_acl).start()
        self.reseal(); self.seal_custody()
        return parent, self.record(parent)

    def test_root_volume_parent_named_operator_rw_masked_rx_is_preserved(self):
        parent, before = self.root_volume_parent()
        self.project()
        self.assertEqual(self.record(parent), before)
        self.assertEqual(before['gid'], self.operator_gid)
        self.assertEqual(before['mode'], 0o755)

    def test_root_volume_parent_named_foreign_writer_is_refused(self):
        self.root_volume_parent(named_uid=self.operator + 1)
        self.refuse()

    def test_root_volume_parent_writing_mask_is_refused(self):
        self.root_volume_parent(mask=7)
        self.refuse()

    def test_root_volume_parent_named_operator_rwx_masked_rx_is_preserved(self):
        parent, before = self.root_volume_parent(permission=7)
        self.project()
        self.assertEqual(self.record(parent), before)

    def test_root_volume_parent_unexpected_operator_rights_are_refused(self):
        self.root_volume_parent(permission=2)
        self.refuse()

    def test_operator_named_writer_is_exact_not_marker_actor(self):
        self.scope_acl = self.acl([(1, 7, 0xffffffff), (2, 7, self.operator),
                                   (2, 1, self.uid), (4, 7, 0xffffffff),
                                   (16, 7, 0xffffffff), (32, 0, 0xffffffff)])
        self.seal_custody(); self.project()

    def test_exact_operator_owned_intermediate_ancestor(self):
        parent = self.scope / 'selected-parent'
        self.mkdir(parent)
        parent.chmod(0o2770)
        s = parent.stat()
        self.virtual[s.st_dev, s.st_ino] = self.operator, self.operator_gid
        graph = parent / 'actor-graph'
        Path(self.row['graphRoot']).rename(graph)
        self.row['graphRoot'] = str(graph)
        self.reseal()
        self.seal_custody()
        self.project()

    def test_exact_root_private_intermediate_ancestor(self):
        parent = self.scope / 'selected-parent'
        self.mkdir(parent)
        graph = parent / 'actor-graph'
        Path(self.row['graphRoot']).rename(graph)
        self.row['graphRoot'] = str(graph)
        self.reseal()
        self.seal_custody()
        self.project()

    def test_foreign_intermediate_owner_denied_even_if_pinned(self):
        parent = self.scope / 'selected-parent'
        self.mkdir(parent)
        s = parent.stat()
        self.virtual[s.st_dev, s.st_ino] = self.uid + 5, self.actor_gid
        graph = parent / 'actor-graph'
        Path(self.row['graphRoot']).rename(graph)
        self.row['graphRoot'] = str(graph)
        self.reseal()
        self.seal_custody()
        self.refuse()

    def test_proof_bool_is_not_integer_identity(self):
        self.receipt['projectionCustody']['schemaVersion'] = True
        self.save_receipt()
        self.refuse()

    def test_no_lease_cli_equivalent_cannot_relax_ancestry(self):
        self.refuse(custody_lease=None)

    def test_receipt_without_custody_cannot_use_lease(self):
        del self.receipt['projectionCustody']
        self.save_receipt()
        self.refuse()

    def test_boolean_admission_callback_is_not_lease_verification(self):
        self.lease.verify_projection = lambda selection: False
        self.refuse()

    def test_wrong_receipted_actor_or_scope_selection(self):
        self.receipt['projectionCustody']['selection']['uid'] += 1
        self.save_receipt()
        self.refuse()

    def test_unmarked_actor_writable_scope_is_not_adopted(self):
        (self.scope / '.stack-installation.json').unlink()
        self.refuse()

    def test_foreign_sibling_not_adopted_or_mutated(self):
        foreign = self.scope / 'foreign'
        self.put(foreign / 'authored.txt', 'synthetic foreign sentinel\n')
        self.refuse(state_root=foreign, destination=foreign / 'releases/r1/runtime')
        self.assertEqual((foreign / 'authored.txt').read_text(), 'synthetic foreign sentinel\n')

    def test_actor_writable_unselected_parent_not_allowed(self):
        foreign = self.scope / 'foreign'
        self.mkdir(foreign)
        proof = self.receipt['projectionCustody']
        proof['directories'][str(foreign)] = self.record(foreign)
        self.save_receipt()
        self.refuse()

    def test_missing_selected_graph_proof(self):
        del self.receipt['projectionCustody']['directories'][self.row['graphRoot']]
        self.save_receipt()
        self.refuse()

    def test_wrong_actor_directory_owner(self):
        s = self.state.stat()
        self.virtual[s.st_dev, s.st_ino] = self.uid + 1, self.actor_gid
        self.seal_custody()  # Even a newly pinned foreign owner is not allowed.
        self.refuse()

    def test_wrong_actor_group(self):
        self.receipt['projectionCustody']['actorGid'] += 1
        self.save_receipt()
        self.refuse()

    def test_actor_owned_new_release_denied(self):
        s = self.slot.stat()
        self.virtual[s.st_dev, s.st_ino] = self.uid, self.actor_gid
        self.seal_custody()
        self.refuse()

    def test_new_release_root_owner_with_foreign_group_is_refused(self):
        s = self.slot.stat()
        self.virtual[s.st_dev, s.st_ino] = p.OWNER, self.operator_gid
        self.seal_custody()
        self.refuse()

    def test_scope_other_access_denied_even_if_receipted(self):
        self.scope.chmod(0o2771)
        self.seal_custody()
        self.refuse()

    def test_foreign_acl_denied_even_if_receipted(self):
        self.scope_acl = self.acl([(1, 7, 0xffffffff), (2, 1, self.uid + 5),
                                  (4, 7, 0xffffffff), (16, 7, 0xffffffff), (32, 0, 0xffffffff)])
        self.seal_custody()
        self.refuse()

    def test_actor_write_acl_denied_even_if_receipted(self):
        self.scope_acl = self.acl([(1, 7, 0xffffffff), (2, 3, self.uid),
                                  (4, 7, 0xffffffff), (16, 7, 0xffffffff), (32, 0, 0xffffffff)])
        self.seal_custody()
        self.refuse()

    def operator_default(self, *, uid=None, gid=None, other=0, duplicate=False):
        rows = [(1, 7, 0xffffffff), (2, 6, self.operator if uid is None else uid),
                (4, 6, 0xffffffff), (8, 6, self.operator_gid if gid is None else gid),
                (16, 6, 0xffffffff), (32, other, 0xffffffff)]
        if duplicate:
            rows.append(rows[1])
        default = self.acl(rows)
        original = p.acl_bytes
        scope = self.scope.stat()
        def fixture_default(fd, name):
            seen = os.fstat(fd)
            if name == 'system.posix_acl_default' and (seen.st_dev, seen.st_ino) == (scope.st_dev, scope.st_ino):
                return default
            return original(fd, name)
        patch.object(p, 'acl_bytes', side_effect=fixture_default).start()
        self.seal_custody()
        return default

    def test_operator_group_only_default_acl_remains_pinned_and_unchanged(self):
        default = self.operator_default()
        before = self.record(self.scope)
        self.project()
        self.assertEqual(self.record(self.scope), before)
        self.assertEqual(before['defaultAcl'], default.hex())

    def test_default_acl_foreign_named_operator_refused(self):
        self.operator_default(uid=self.operator + 1); self.refuse()

    def test_default_acl_foreign_named_group_refused(self):
        self.operator_default(gid=self.operator_gid + 1); self.refuse()

    def test_default_acl_public_access_refused(self):
        self.operator_default(other=5); self.refuse()

    def test_default_acl_duplicate_entries_refused(self):
        self.operator_default(duplicate=True); self.refuse()

    def test_default_acl_denied_even_if_receipted(self):
        original = p.acl_bytes
        def default_acl(fd, name):
            return self.scope_acl if name == 'system.posix_acl_default' else original(fd, name)
        with patch.object(p, 'acl_bytes', side_effect=default_acl):
            self.seal_custody()
            self.refuse()

    def test_marker_must_remain_exact_root_owned(self):
        s = (self.scope / '.stack-installation.json').stat()
        self.virtual[s.st_dev, s.st_ino] = self.uid, self.actor_gid
        self.refuse()

    def test_marker_hardlink_denied(self):
        os.link(self.scope / '.stack-installation.json', self.scope / 'marker-alias')
        self.refuse()

    def test_scope_mount_boundary_never_falls_back_to_plain_open(self):
        original = p.child_open
        def alias(parent, name, flags):
            if name == self.scope.name:
                raise OSError(18, 'synthetic EXDEV')
            return original(parent, name, flags)
        with patch.object(p, 'child_open', side_effect=alias):
            self.refuse()

    def test_graph_symlink_denied_even_when_pointing_to_selected_inode(self):
        graph = Path(self.row['graphRoot'])
        moved = self.scope / 'moved-graph'
        graph.rename(moved)
        graph.symlink_to(moved, target_is_directory=True)
        self.refuse()

    def test_pinned_mount_alias_identity_mismatch(self):
        self.receipt['projectionCustody']['directories'][str(self.scope)]['mountId'] += 1
        self.save_receipt()
        self.refuse()

    def mutate_during_stage(self, callback):
        original = p.write_file
        called = False
        def mutate(*args, **kwargs):
            nonlocal called
            original(*args, **kwargs)
            if not called:
                called = True
                callback()
        with patch.object(p, 'write_file', side_effect=mutate):
            self.refuse()

    def test_intent_cas_changed_with_legitimate_ownership(self):
        self.mutate_during_stage(lambda: self.put(self.install / '.install-intent.json', '{}\n'))

    def test_marker_content_changed_with_legitimate_ownership(self):
        self.mutate_during_stage(lambda: self.put(self.scope / '.stack-installation.json', '{}\n'))

    def test_acl_change_during_stage(self):
        self.mutate_during_stage(lambda: setattr(self, 'scope_acl', b''))

    def test_custody_mode_change_during_stage(self):
        self.mutate_during_stage(lambda: self.state.chmod(0o750))

    def test_current_pointer_change_during_stage(self):
        self.mutate_during_stage(lambda: (self.state / 'current').symlink_to('releases/previous'))

    def test_existing_exact_previous_current_is_pinned(self):
        (self.state / 'current').symlink_to('releases/previous')
        self.seal_custody()
        self.project()
        self.assertEqual(os.readlink(self.state / 'current'), 'releases/previous')

    def test_current_cannot_name_preparing_release(self):
        (self.state / 'current').symlink_to('releases/r1')
        self.seal_custody()
        self.refuse()

    def test_current_cannot_escape_selected_state(self):
        (self.state / 'current').symlink_to('../foreign')
        self.seal_custody()
        self.refuse()

    def test_current_must_not_be_regular_authored_file(self):
        self.put(self.state / 'current', 'foreign authored pointer')
        self.refuse()

    def test_canonical_lease_loss_during_stage(self):
        self.mutate_during_stage(lambda: setattr(self.lease, 'valid', False))

    def test_marker_inode_replaced_with_identical_bytes_during_stage(self):
        def replace():
            marker = self.scope / '.stack-installation.json'
            original = marker.read_bytes()
            marker.rename(self.scope / 'old-marker')
            self.put(marker, original)
        self.mutate_during_stage(replace)

    def test_new_release_rename_and_replacement_during_stage(self):
        moved = self.slot.with_name('moved')
        def replace():
            self.slot.rename(moved)
            self.mkdir(self.slot)
        self.mutate_during_stage(replace)
        self.assertFalse((moved / 'runtime').exists())

    def test_reparent_state_graph_during_stage(self):
        moved = self.scope / 'moved-state'
        def replace():
            self.state.rename(moved)
            self.mkdir(self.slot)
            # Supply a readable previous sentinel for the no-mutation check.
            self.put(self.previous, 'previous private runtime stays unchanged\n')
        self.mutate_during_stage(replace)
        self.assertFalse((moved / 'releases/r1/runtime').exists())

    def test_scope_rename_and_replacement_during_stage(self):
        moved = self.base / 'moved-scope'
        def replace():
            self.scope.rename(moved)
            self.mkdir(self.slot)
            self.put(self.previous, 'previous private runtime stays unchanged\n')
        self.mutate_during_stage(replace)
        self.assertFalse((moved / 'actor-state/releases/r1/runtime').exists())

    def test_lease_loss_at_publish_is_not_accepted_for_handoff(self):
        original = p.publish
        def race(parent, stage, destination):
            original(parent, stage, destination)
            self.lease.valid = False
        with patch.object(p, 'publish', side_effect=race), self.assertRaises(p.Refusal):
            self.project()
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o700)
        self.assertEqual(self.destination.stat().st_uid, os.getuid())
        self.assertEqual(self.previous.read_text(), 'previous private runtime stays unchanged\n')

    def test_rename_at_publish_is_not_accepted_or_handed_to_actor(self):
        moved = self.slot.with_name('moved')
        original = p.publish
        def race(parent, stage, destination):
            self.slot.rename(moved)
            self.mkdir(self.slot)
            original(parent, stage, destination)
        with patch.object(p, 'publish', side_effect=race), self.assertRaises(p.Refusal):
            self.project()
        self.assertFalse(self.destination.exists())
        # Publication via retained FD cannot be redirected into the replacement
        # tree. Any moved result is still inert/root0700, not accepted ownership.
        self.assertEqual(stat.S_IMODE((moved / 'runtime').stat().st_mode), 0o700)
        self.assertEqual((moved / 'runtime').stat().st_uid, os.getuid())


class OwnerImportProjection(unittest.TestCase):
    mkdir = Projection.mkdir
    put = Projection.put
    reseal = Projection.reseal
    save_receipt = Projection.save_receipt
    args = Projection.args
    project = Projection.project
    refuse = Projection.refuse

    def setUp(self):
        Projection.setUp(self)
        self.owner_password = 'synthetic-owner-initial-password-sentinel'
        self.realm = self.config / p.IDP_REALM
        self.put(self.realm, p.encoded({'realm': 'webservices', 'users': [
            {'id': 'synthetic-owner', 'credentials': [
                {'type': 'password', 'value': self.owner_password, 'temporary': True}]}]}))

    def test_native_password_realm_only_for_exact_idp(self):
        self.ir['services']['keycloak'] = {'placement': 'rootless', 'rootlessDomain': 'test-runners',
                                         'environment': {}, 'volumes': ['./configs/keycloak/realm:/realm:ro']}
        self.row['services'].append('keycloak')
        self.reseal()
        self.project()
        for node in self.destination.rglob('*'):
            if node.is_file() and self.owner_password.encode() in node.read_bytes():
                self.assertEqual(node, self.destination / 'configs' / p.IDP_REALM)

    def test_native_password_never_in_test_actor_environment(self):
        self.ir['services']['test-runner']['environment']['INITIAL_PASSWORD'] = self.owner_password
        self.reseal()
        self.refuse()

    def test_native_password_never_in_other_config(self):
        self.put(self.config / 'shared/public.json', self.owner_password)
        self.refuse()

    def test_test_actor_cannot_mount_native_password_realm(self):
        self.ir['services']['test-runner']['volumes'] = ['./configs/keycloak/realm:/realm']
        self.reseal()
        self.refuse()

    def test_json_escaped_owner_password_outside_exact_realm_denied(self):
        self.owner_password = 'synthetic-quote-"-and-unicode-\u00e9-password'
        self.put(self.realm, p.encoded({'users': [{'credentials': [
            {'type': 'password', 'value': self.owner_password}]}]}))
        self.put(self.config / 'shared/public.json', json.dumps({'leak': self.owner_password}))
        self.refuse()

    def test_root_derivation_master_still_denied_in_owner_realm(self):
        self.ir['services']['keycloak'] = {'placement': 'rootless', 'rootlessDomain': 'test-runners',
                                         'environment': {}, 'volumes': ['./configs/keycloak/realm:/realm']}
        self.row['services'].append('keycloak')
        self.put(self.realm, p.encoded({'users': [], 'master': 'ROOT_ONLY_MASTER_SENTINEL'}))
        self.reseal()
        self.refuse()

    def test_owner_password_introduced_during_stage_refused(self):
        original = p.write_file
        def mutate(*args, **kwargs):
            original(*args, **kwargs)
            self.put(self.realm, p.encoded({'users': []}))
        with patch.object(p, 'write_file', side_effect=mutate):
            self.refuse()



if __name__ == '__main__':
    unittest.main()
