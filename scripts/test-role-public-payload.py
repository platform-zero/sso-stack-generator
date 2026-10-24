#!/usr/bin/env python3
"""Isolated real FD copies; synthetic UID/ACL/accounts/lock/inactivity only.

No host install, native commands, private inputs, network, chown or Git actions.
Reuses the canonical owner's temp-root identity model (never its handoff calls).
"""
import argparse
import copy
import errno
import importlib.util
import json
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('public_role_owner_fixture', HERE / 'test-native-runtime-projection-owner.py')
fixture = importlib.util.module_from_spec(spec)
exec(compile(Path(spec.origin).read_bytes(), spec.origin, 'exec'), fixture.__dict__)
spec = importlib.util.spec_from_file_location('public_role_tested',
    HERE.parent / 'runtime-generator/podman-ops/prepare-role-public-payload.py')
c = importlib.util.module_from_spec(spec)
exec(compile(Path(spec.origin).read_bytes(), spec.origin, 'exec'), c.__dict__)


class PublicPayload(fixture.Owner):
    # Only this class's methods are collected below, not inherited owner tests.
    def setUp(self):
        super().setUp()
        # All deletions here are fixture setup, exclusively under its temp root.
        (self.slot / 'build/selected/source.sh').unlink()
        (self.slot / 'build/selected').rmdir()
        (self.slot / 'build').rmdir()
        self.put(self.release / 'site/components.lock.json', b'{"modules":[]}\n')
        self.put(self.release / 'build/stack.config/mastodon/mastodon.env', b'UNRENDERED=${DOMAIN}\n')
        self.put(self.release / 'build/stack.config/mastodon/public.json', b'{"public":true}\n')
        self.put(self.release / 'build/empty.env.template', b'NOT_PUBLIC=1\n')
        self.put(self.release / 'build/secret.sops.json', b'encrypted-not-public\n')
        self.put(self.release / 'build/stack.env', b'NEVER_COPY=1\n')
        self.put(self.release / 'build/selected/source.sh', b'#!/bin/sh\ntrue\n')
        (self.release / 'build/selected/source.sh').chmod(0o755)
        for target in c.o.native.TARGETS:
            self.put(self.release / 'quadlet/rootless-test-runners' / target, b'[Unit]\n')
        # Selected local build with an exact COPY unaffected by omitted env.
        self.ir['services']['test-runner']['build'] = dict(context='./selected', containerfile='Containerfile')
        self.put(self.release / 'build/selected/Containerfile',
                 b'FROM scratch\nCOPY ["source.sh", "/source.sh"]\n')
        self.reseal()
        # Execute the helper using the exact same canonical owner module that
        # the existing fixture models. Production has no injectable callback.
        patch.object(c, 'o', fixture.o).start()
        patch.object(c, 'p', fixture.p).start()
        patch.object(os, 'chown', side_effect=AssertionError('no chown')).start()
        patch.object(os, 'fchown', side_effect=AssertionError('no fchown')).start()
        patch.object(c.o.journal.subprocess, 'run', side_effect=AssertionError('no native calls')).start()

    def run_copy(self):
        return c.prepare(self.release, self.domain)

    def assert_refused_empty(self):
        with self.assertRaises((ValueError, OSError)):
            self.run_copy()
        self.assertEqual(os.listdir(self.slot), [])

    def test_generated_dot_prefixed_containerfile_at_root_context(self):
        self.ir['services']['test-runner']['build'] = dict(context='.', containerfile='./selected/Containerfile')
        self.put(self.release / 'build/selected/Containerfile',
                 b'FROM scratch\nCOPY ["selected/source.sh", "/source.sh"]\n')
        self.reseal()
        self.run_copy()
        self.assertTrue((self.slot / 'build/selected/source.sh').is_file())

    def test_parent_traversal_containerfile_refuses_before_copy(self):
        self.ir['services']['test-runner']['build']['containerfile'] = './../Containerfile'
        self.reseal()
        self.assert_refused_empty()

    def test_public_exact_copy_skip_at_creation_no_handoff(self):
        before = (self.install / '.install-intent.json').read_bytes()
        writes = []
        raw = os.open
        def opened(path, flags, *args, **kwargs):
            if flags & os.O_CREAT:
                writes.append(str(path))
            return raw(path, flags, *args, **kwargs)
        with patch.object(os, 'open', side_effect=opened):
            proof = self.run_copy()
        self.assertEqual(before, (self.install / '.install-intent.json').read_bytes())
        self.assertFalse(proof['ownershipTransferred'])
        self.assertFalse(proof['activationAuthorized'])
        self.assertTrue(c.o.lock_held.called)
        self.assertTrue(c.o.inactive.called)
        self.assertEqual(proof['omittedPaths'], sorted(['build/empty.env.template', 'build/secret.sops.json',
            'build/stack.env', 'build/stack.config/mastodon/mastodon.env']))
        self.assertFalse(any(c.omitted(Path(name).name) for name in writes))
        self.assertEqual(stat.S_IMODE(self.slot.stat().st_mode), 0o700)
        self.assertEqual(self.slot.stat().st_uid, 0)
        self.assertFalse((self.slot / 'runtime').exists())
        self.assertFalse((self.slot / 'site/manifest.json').exists())
        self.assertEqual(self.mutations, [])
        for name, row in proof['files'].items():
            path = self.slot / name
            self.assertEqual((path.stat().st_uid, path.stat().st_gid), (0, 0))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), row['mode'])
            if not row['directory']:
                self.assertEqual(path.read_bytes(), (self.release / name).read_bytes())
        self.assertEqual(stat.S_IMODE((self.slot / 'build/selected/source.sh').stat().st_mode), 0o755)
        self.assertNotIn('root-master-sentinel', json.dumps(proof))
        self.assertEqual(len(proof['localBuildCopyClosure']), 1)

    def test_empty_domain_four_targets_no_aggregate_read(self):
        for name in ('test-runner', 'runner80'):
            del self.ir['services'][name]
        self.row['services'] = []
        self.reseal()
        (self.release / 'runtime/stack.env').unlink()
        proof = self.run_copy()
        self.assertFalse((self.slot / 'build').exists())
        self.assertEqual(proof['omittedPaths'], [])
        self.assertEqual(proof['localBuildCopyClosure'], [])
        self.assertEqual(len([v for v in proof['files'].values() if not v['directory']]), 5)

    def test_unknown_preexisting_leaf_refused_without_removal(self):
        self.put(self.slot / 'unknown', b'keep')
        with self.assertRaises(ValueError): self.run_copy()
        self.assertEqual((self.slot / 'unknown').read_bytes(), b'keep')

    def test_root_material_refused_before_writes(self):
        self.put(self.release / 'build/selected/leak.txt', b'prefix root-master-sentinel suffix')
        self.assert_refused_empty()

    def test_empty_root_material_is_not_blanket_refusal(self):
        self.put(self.release / 'runtime/stack.env', b'DOMAIN=synthetic.invalid\nP0_DERIVATION_MASTER_KEY=\n')
        self.run_copy()

    def test_copy_env_dependency_refused_before_writes(self):
        self.ir['services']['test-runner']['build']['context'] = './stack.config/mastodon'
        self.put(self.release / 'build/stack.config/mastodon/Containerfile',
                 b'FROM scratch\nCOPY mastodon.env /env\n')
        self.reseal()
        self.assert_refused_empty()

    def test_copy_parent_escape_refused_before_writes(self):
        self.put(self.release / 'build/selected/Containerfile',
                 b'FROM scratch\nCOPY ../private /env\n')
        self.assert_refused_empty()

    def test_registry_mastodon_needs_no_omitted_build_env(self):
        self.ir['services']['mastodon'] = dict(placement='rootless', rootlessDomain=self.domain,
            image='ghcr.io/mastodon/mastodon:reviewed', environment={}, volumes=[])
        self.row['services'].append('mastodon')
        self.reseal()
        proof = self.run_copy()
        self.assertEqual([row['service'] for row in proof['localBuildCopyClosure']], ['test-runner'])
        self.assertIn('build/stack.config/mastodon/mastodon.env', proof['omittedPaths'])

    def test_default_dockerfile_copy_closure(self):
        del self.ir['services']['test-runner']['build']['containerfile']
        self.put(self.release / 'build/selected/Dockerfile', b'FROM scratch\nCOPY source.sh /app\n')
        (self.release / 'build/selected/Containerfile').unlink()
        self.reseal()
        proof = self.run_copy()
        self.assertEqual(proof['localBuildCopyClosure'][0]['path'], 'build/selected/Dockerfile')

    def test_outer_leaf_acl_refused(self):
        self.acls[self.key(self.slot)] = (fixture.acl(), b'')
        self.assert_refused_empty()

    def test_outer_leaf_wrong_owner_refused(self):
        self.set_owner(self.slot, self.row['uid'], self.row['uid'])
        self.assert_refused_empty()

    def test_outer_leaf_wrong_mode_refused(self):
        self.slot.chmod(0o755)
        self.assert_refused_empty()

    def test_primary_operator_group_drift_refused(self):
        self.operator.pw_gid = 1001
        self.assert_refused_empty()

    def test_multistage_copy_does_not_read_host_inputs(self):
        self.put(self.release / 'build/selected/Containerfile', b'FROM scratch AS builder\n'
            b'COPY source.sh /source.sh\nFROM scratch\nCOPY --from=builder /source.sh /out\n')
        self.run_copy()

    def test_deferred_copy_refused(self):
        self.put(self.release / 'build/selected/Containerfile', b'FROM scratch\nONBUILD COPY . /app\n')
        self.assert_refused_empty()

    def test_root_material_cross_chunk_refused(self):
        self.put(self.release / 'build/selected/leak.txt', b'q' * (128 * 1024 - 8) +
                 b'root-master-sentinel' + b'z' * 128)
        self.assert_refused_empty()

    def test_setid_source_refused(self):
        (self.release / 'build/selected/source.sh').chmod(0o4755)
        self.assert_refused_empty()

    def test_submount_openat2_refusal_is_not_fallback(self):
        raw = c.p.child_open
        def crossing(parent, name, flags):
            if name == 'build/selected/source.sh':
                raise OSError(errno.EXDEV, 'synthetic no-xdev refusal')
            return raw(parent, name, flags)
        with patch.object(c.p, 'child_open', side_effect=crossing):
            self.assert_refused_empty()

    def test_copy_directory_including_omitted_env_refused(self):
        self.ir['services']['test-runner']['build']['context'] = '.'
        self.ir['services']['test-runner']['build']['containerfile'] = 'selected/Containerfile'
        self.put(self.release / 'build/selected/Containerfile', b'FROM scratch\nCOPY . /app\n')
        self.reseal()
        self.assert_refused_empty()

    def test_copy_glob_omission_refused(self):
        self.ir['services']['test-runner']['build']['context'] = './stack.config/mastodon'
        self.put(self.release / 'build/stack.config/mastodon/Containerfile', b'FROM scratch\nCOPY * /app/\n')
        self.reseal()
        self.assert_refused_empty()

    def test_dynamic_copy_refused(self):
        self.put(self.release / 'build/selected/Containerfile', b'FROM scratch\nCOPY ${INPUT} /app\n')
        self.assert_refused_empty()

    def test_source_link_refused(self):
        (self.release / 'build/selected/link').symlink_to(self.release / 'bundle.json')
        self.assert_refused_empty()

    def test_source_directory_link_refused(self):
        (self.release / 'build/alias').symlink_to(self.release / 'build/selected', target_is_directory=True)
        self.assert_refused_empty()

    def test_source_hardlink_refused(self):
        os.link(self.release / 'build/selected/source.sh', self.release / 'build/selected/alias')
        self.assert_refused_empty()

    def test_source_fifo_refused_nonblocking(self):
        os.mkfifo(self.release / 'build/selected/pipe', 0o600)
        self.assert_refused_empty()

    def test_source_acl_refused(self):
        self.acls[self.key(self.release / 'build/selected/source.sh')] = (fixture.acl(), b'')
        self.assert_refused_empty()

    def test_omitted_symlink_still_refused(self):
        (self.release / 'build/selected/x.env').symlink_to(self.release / 'bundle.json')
        self.assert_refused_empty()

    def test_receipt_hash_and_cas_refused(self):
        self.put(self.release / 'stack.ir.json', b'{}\n')
        self.assert_refused_empty()

    def test_receipt_intent_mismatch_refused(self):
        self.put(self.install / '.install-intent.json', fixture.p.encoded(dict(self.prior, phase='active')))
        self.assert_refused_empty()

    def test_lease_refused(self):
        c.o.lock_held.side_effect = ValueError('synthetic missing inherited lease')
        self.assert_refused_empty()

    def test_running_actor_refused(self):
        c.o.inactive.side_effect = ValueError('synthetic running actor')
        self.assert_refused_empty()

    def test_wrong_actor_account_refused(self):
        self.accounts[self.row['user']].pw_uid = 999
        self.assert_refused_empty()

    def test_scope_marker_cas_refused(self):
        self.put(self.scope / '.stack-installation.json', b'{}\n')
        self.assert_refused_empty()

    def test_mapped_identity_change_refused(self):
        c.o.storage.namespace_root_id.side_effect = ValueError('synthetic subordinate drift')
        self.assert_refused_empty()

    def test_deadline_refused_before_creation(self):
        with patch.object(c, 'MAX_SECONDS', -1): self.assert_refused_empty()

    def test_size_bound_refused_before_creation(self):
        with patch.object(c, 'MAX_TOTAL', 1): self.assert_refused_empty()

    def test_partial_failure_stays_inert_no_adoption(self):
        raw = c.stream
        def fail(fd, deadline, denied=(), output=None):
            if output is not None: raise ValueError('synthetic interrupted copy')
            return raw(fd, deadline, denied, output)
        with patch.object(c, 'stream', side_effect=fail):
            with self.assertRaises(ValueError): self.run_copy()
        self.assertTrue(os.listdir(self.slot))
        self.assertEqual((self.slot.stat().st_uid, stat.S_IMODE(self.slot.stat().st_mode)), (0, 0o700))
        before = sorted(str(path) for path in self.slot.rglob('*'))
        with self.assertRaises(ValueError): self.run_copy()
        self.assertEqual(before, sorted(str(path) for path in self.slot.rglob('*')))

    def test_destination_same_content_inode_swap_refused(self):
        raw = c.stream
        changed = False
        def mutate(fd, deadline, denied=(), output=None):
            nonlocal changed
            result = raw(fd, deadline, denied, output)
            path = self.slot / 'site/components.lock.json'
            if output is not None and path.exists() and not changed:
                changed = True
                # Same bytes and mode, but a new inode: hash-only CAS is insufficient.
                replacement = self.slot / 'replacement'
                replacement.write_bytes(path.read_bytes())
                replacement.chmod(stat.S_IMODE(path.stat().st_mode))
                os.replace(replacement, path)
            return result
        with patch.object(c, 'stream', side_effect=mutate):
            with self.assertRaises(ValueError): self.run_copy()
        self.assertTrue(changed)
        self.assertEqual(self.slot.stat().st_uid, 0)

    def test_scope_parent_drift_during_copy_refused(self):
        raw = c.stream
        changed = False
        def mutate(fd, deadline, denied=(), output=None):
            nonlocal changed
            result = raw(fd, deadline, denied, output)
            if output is not None and not changed:
                changed = True
                (self.scope / 'state').chmod(0o2775)
            return result
        with patch.object(c, 'stream', side_effect=mutate):
            with self.assertRaises(ValueError): self.run_copy()
        self.assertEqual(stat.S_IMODE(self.slot.stat().st_mode), 0o700)

    def test_source_mutation_during_copy_kept_inert(self):
        raw = c.stream
        changed = False
        def mutate(fd, deadline, denied=(), output=None):
            nonlocal changed
            result = raw(fd, deadline, denied, output)
            if output is not None and not changed:
                changed = True
                self.put(self.release / 'build/selected/source.sh', b'changed\n')
            return result
        with patch.object(c, 'stream', side_effect=mutate):
            with self.assertRaises(ValueError): self.run_copy()
        self.assertEqual(self.slot.stat().st_uid, 0)

    def test_external_operator_ancestry_remains_unchanged(self):
        # This fixture's ordinary scope also has exact operator ACLs. Snapshot
        # every scoped parent and verify none is chmod/chown/ACL-mutated.
        paths = [self.scope, self.scope / 'state', self.state, self.state / 'releases']
        before = {path: (path.stat().st_mode, path.stat().st_uid, path.stat().st_gid,
                        self.acls.get(self.key(path))) for path in paths}
        self.run_copy()
        self.assertEqual(before, {path: (path.stat().st_mode, path.stat().st_uid, path.stat().st_gid,
                        self.acls.get(self.key(path))) for path in paths})


class ExternalOperator(PublicPayload):
    external = True

    def test_actual_external_acl_model_untouched(self):
        mode = self.external_parent.stat().st_mode
        acls = self.acls[self.key(self.external_parent)]
        self.run_copy()
        self.assertEqual(self.external_parent.stat().st_mode, mode)
        self.assertEqual(self.acls[self.key(self.external_parent)], acls)


class ClosureParser(unittest.TestCase):
    """Pure parser models only: recipe reads, NOT identity/ownership, are modeled."""

    def parse(self, text, *, context='.', containerfile='./Containerfile', files=(),
              directories=(), exclusions=()):
        base = 'build' if context in ('.', './build') else 'build/' + context.removeprefix('./')
        path = base + '/' + containerfile.removeprefix('./')
        nodes = {name: dict(directory=True) for name in ('build', base, *directories)}
        nodes.update({name: dict(directory=False) for name in files})
        nodes[path] = dict(directory=False, sha256=c.p.sha(text.encode()))
        services = {'modeled': {'build': dict(context=context, containerfile=containerfile)}}
        with patch.object(c, 'read_small', return_value=text) as reader:
            result = c.closure(None, services, nodes, list(exclusions))
        reader.assert_called_once_with(None, path, nodes)
        return result

    def test_actual_shape_root_build_alias_and_dot_recipe(self):
        result = self.parse('FROM scratch\nCOPY stack.containers/app/source.py /app/\n',
            context='./build', containerfile='./stack.containers/app/Containerfile',
            files=['build/stack.containers/app/source.py'])
        self.assertEqual(result[0]['path'], 'build/stack.containers/app/Containerfile')

    def test_actual_shape_module_relative_context(self):
        result = self.parse('FROM scratch\nCOPY exporter.py /app/\n',
            context='./stack.containers/exporter',
            files=['build/stack.containers/exporter/exporter.py'])
        self.assertEqual(len(result), 1)

    def test_actual_shape_variable_chown_and_multisource_continuation(self):
        self.parse('FROM scratch\nCOPY --chown=${NB_UID}:${NB_GID} '
            'one.py \\\n two.py /app/\n', files=['build/one.py', 'build/two.py'])

    def test_actual_shape_prior_stage_chmod_and_jar_glob(self):
        self.parse('FROM scratch AS builder\nCOPY libs/*-all.jar /libs/\n'
            'FROM scratch\nCOPY --from=builder --chmod=0755 /libs/ /app/\n',
            files=['build/libs/test-1-all.jar'])

    def test_json_copy_and_add_literal_public_inputs(self):
        self.parse('FROM scratch\nCOPY ["one.py", "/app/one.py"]\n'
            'ADD two.py /app/\n', files=['build/one.py', 'build/two.py'])

    def test_copy_and_add_broad_inputs_cannot_hide_omitted_env(self):
        for instruction in ('COPY', 'ADD'):
            for source in ('.', './', '*', 'stack.config', 'stack.config/*'):
                with self.subTest(instruction=instruction, source=source):
                    with self.assertRaisesRegex(ValueError, 'omitted private-named input'):
                        self.parse(f'FROM scratch\n{instruction} {source} /app/\n',
                            directories=['build/stack.config', 'build/stack.config/mastodon'],
                            exclusions=['build/stack.config/mastodon/mastodon.env'])

    def test_copy_options_cannot_hide_omitted_env(self):
        for flags in ('--chown=${UID}:${GID}', '--chmod=0755', '--exclude=*.env'):
            with self.subTest(flags=flags):
                with self.assertRaises(ValueError):
                    self.parse(f'FROM scratch\nCOPY {flags} . /app/\n',
                        exclusions=['build/mastodon.env'])

    def test_each_multisource_dependency_must_be_public(self):
        for source in ('missing.py', 'mastodon.env'):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    self.parse(f'FROM scratch\nCOPY one.py {source} /app/\n',
                        files=['build/one.py'], exclusions=['build/mastodon.env'])

    def test_unproven_external_stage_cannot_bypass_local_closure(self):
        with self.assertRaisesRegex(ValueError, 'unproven external build copy'):
            self.parse('FROM scratch\nCOPY --from=unproven /data /app/\n')

    def test_context_and_recipe_escape_remain_refused(self):
        for context, containerfile in (('./../outside', 'Containerfile'),
                                       ('.', './../Containerfile')):
            with self.subTest(context=context, containerfile=containerfile):
                with self.assertRaises(ValueError):
                    self.parse('FROM scratch\n', context=context, containerfile=containerfile)


def actual_shape_suite(path):
    """Explicit external PUBLIC fixture; no discovery or copying into the repo.

    Each descriptor is an independent test, so one refusal does not suppress
    remaining recipes. Only read_small is replaced with immutable public text;
    prepare/snapshot/custody and filesystem ownership are never simulated here.
    """
    raw = Path(path).read_bytes()
    data = json.loads(raw)
    recipes, bodies = data['recipes'], data['containerfiles']
    nodes, exclusions = data['nodes'], data['omitted']
    if not recipes or any(name in nodes for name in exclusions):
        raise ValueError('public fixture lacks recipes or includes omitted nodes')
    for name, text in bodies.items():
        if nodes[name]['directory'] or nodes[name]['sha256'] != c.p.sha(text.encode()):
            raise ValueError('public fixture recipe hash differs: ' + name)
    print('PUBLIC CLOSURE FIXTURE: sha256=' + c.p.sha(raw) +
          f'; {len(recipes)} descriptors, {len(bodies)} bodies, {len(nodes)} nodes; '
          'STALE source-shape parser evidence ONLY, not candidate/FD/ownership/installed proof',
          flush=True)

    class ActualPublicShape(unittest.TestCase):
        def check(self, selected):
            # Independent copies prevent a parser mutation from blessing later tests.
            inventory, omitted_paths = copy.deepcopy(nodes), list(exclusions)
            immutable_bodies = dict(bodies)
            with patch.object(c, 'read_small',
                    side_effect=lambda root, name, pins: immutable_bodies[name]):
                result = c.closure(None, copy.deepcopy(selected), inventory, omitted_paths)
            self.assertEqual(len(result), len(selected))
            for row in result:
                self.assertEqual(row['sha256'], nodes[row['path']]['sha256'])
            self.assertEqual(inventory, nodes)
            self.assertEqual(omitted_paths, exclusions)

        def test_all_descriptors_together(self):
            self.check(recipes)

    for name, descriptor in sorted(recipes.items()):
        def test(self, name=name, descriptor=descriptor):
            self.check({name: descriptor})
        setattr(ActualPublicShape, 'test_recipe_' + name.replace('-', '_'), test)
    return unittest.defaultTestLoader.loadTestsFromTestCase(ActualPublicShape)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public-closure-fixture', type=Path,
        help='explicit external public descriptor/body/path inventory; parser evidence only')
    parser.add_argument('--parser-only', action='store_true',
        help='skip the separately scoped real-FD copy/lease tests')
    args = parser.parse_args()
    suite = unittest.TestSuite()
    if not args.parser_only:
        suite.addTests(PublicPayload(name) for name, value in PublicPayload.__dict__.items()
                       if name.startswith('test_') and callable(value))
        suite.addTest(ExternalOperator('test_actual_external_acl_model_untouched'))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(ClosureParser))
    if args.public_closure_fixture:
        suite.addTests(actual_shape_suite(args.public_closure_fixture))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
