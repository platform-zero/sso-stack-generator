#!/usr/bin/env python3
"""Synthetic standalone admission only; no native installer or host mount reads."""
import copy
import importlib.util
import os
from pathlib import Path
import re
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('standalone_fixtures',
    Path(__file__).with_name('test-agent-vm-bundle.py'))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
verifier = fixtures.module


class SecretBoundaries(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.StandaloneBundle()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.ir = self.fixture.ir
        self.domains = self.fixture.domains
        self.scope = '/tmp/standalone-volumes'

    def verify(self):
        self.fixture.seal()
        return verifier.verify(self.root)

    def app(self, mounts, placement='rootless'):
        self.ir['services']['app'] = {'placement': placement, 'rootlessDomain': 'apps', 'volumes': mounts}

    def mail(self, placement='rootful'):
        self.ir['volumes']['mail_tls'] = {'hostPath': self.scope + '/mail_tls',
            'rootlessStrategy': 'shared', 'rootlessAccess': 'read-only'}
        self.ir['services']['mailserver'] = {'placement': placement, 'rootlessDomain': 'apps',
            'volumes': ['mail_tls:/caddy-mail:ro']}

    def alloy(self):
        self.ir['services']['alloy'] = {'placement': 'rootful', 'environment': {
            'STACK_LOG_UID_REGEX': '0|42',
            'STACK_LOG_UNIT_REGEX': '^(webservices-alloy[.]service;|webservices-caddy[.]service;)$'}}

    def test_named_and_path_signing_store_aliases_refused_for_every_other_actor(self):
        self.ir['volumes']['innocent'] = {'hostPath': self.scope + '/caddy_certs', 'rootlessStrategy': 'copy'}
        for placement in ('rootful', 'rootless'):
            for source in ('caddy_certs', 'innocent', self.scope + '/caddy_certs',
                           self.scope + '/caddy_certs/pki/authorities/local', self.scope):
                for mount in (source + ':/keys:ro', {'source': source, 'target': '/keys', 'read_only': True}):
                    with self.subTest(placement=placement, mount=mount):
                        self.app([mount], placement)
                        with self.assertRaisesRegex(ValueError, 'signing store consumer'):
                            self.verify()

    def test_caddy_alone_can_mount_exact_signing_store_alias(self):
        self.ir['volumes']['private_alias'] = {'hostPath': self.scope + '/caddy_certs'}
        mounts = self.ir['services']['caddy']['volumes']
        mounts[1] = {'source': 'private_alias', 'target': '/certs'}
        self.verify()
        mounts[1] = self.scope + '/caddy_certs:/certs'
        self.verify()
        mounts[1] = self.scope + '/caddy_certs/pki:/certs'
        with self.assertRaisesRegex(ValueError, 'signing store consumer'):
            self.verify()

    def test_rootless_or_foreign_caddy_is_not_signing_authority(self):
        self.ir['services']['caddy']['placement'] = 'rootless'
        self.ir['services']['caddy']['rootlessDomain'] = 'apps'
        with self.assertRaisesRegex(ValueError, 'selected rootful Caddy'):
            self.verify()
        self.ir['services']['caddy']['placement'] = 'rootful'
        self.ir['services']['caddy-other'] = copy.deepcopy(self.ir['services']['caddy'])
        with self.assertRaisesRegex(ValueError, 'signing store consumer'):
            self.verify()

    def test_signing_store_sharing_metadata_refused_even_without_consumer(self):
        for field, value in (('rootlessStrategy', 'shared'), ('rootlessAccess', 'read-only')):
            with self.subTest(field=field):
                self.ir['volumes']['caddy_certs'][field] = value
                with self.assertRaisesRegex(ValueError, 'cannot grant rootless'):
                    self.verify()
                self.ir['volumes']['caddy_certs'].pop(field)

    def test_missing_or_overlapping_trust_authority_refused(self):
        saved = self.ir['volumes'].pop('caddy_certs')
        with self.assertRaisesRegex(ValueError, 'selected rootful Caddy'):
            self.verify()
        self.ir['volumes']['caddy_certs'] = saved
        for path in (self.scope + '/caddy_certs', self.scope + '/caddy_certs/public'):
            self.ir['volumes']['caddy_ca']['hostPath'] = path
            with self.assertRaisesRegex(ValueError, 'roots overlap'):
                self.verify()

    def test_public_bundle_reads_allow_exact_named_path_and_file_aliases(self):
        self.ir['volumes']['public_alias'] = {'hostPath': self.scope + '/caddy_ca',
            'rootlessStrategy': 'shared', 'rootlessAccess': 'read-only'}
        for source in ('caddy_ca', 'public_alias', self.scope + '/caddy_ca',
                       self.scope + '/caddy_ca/caddy-ca.crt'):
            for mount in (source + ':/ca:ro', {'source': source, 'target': '/ca', 'read_only': True}):
                with self.subTest(mount=mount):
                    self.app([mount])
                    self.verify()

    def test_public_bundle_writes_relabels_and_other_files_refused(self):
        for mount in ('caddy_ca:/ca', 'caddy_ca:/ca:rw', 'caddy_ca:/ca:ro,U',
                      'caddy_ca:/ca:ro,Z', self.scope + '/caddy_ca/other.pem:/ca:ro',
                      {'source': 'caddy_ca', 'target': '/ca', 'read_only': False}):
            with self.subTest(mount=mount):
                self.app([mount])
                with self.assertRaisesRegex(ValueError, 'public trust consumer'):
                    self.verify()

    def test_public_and_leaf_aliases_cannot_use_actor_writable_copy_policy(self):
        self.mail('rootless')
        for protected, service, target in (('caddy_ca', 'app', '/ca'),
                                            ('mail_tls', 'mailserver', '/caddy-mail')):
            with self.subTest(protected=protected):
                self.ir['volumes']['alias'] = {'hostPath': self.scope + '/' + protected}
                if service == 'app':
                    self.app(['alias:' + target + ':ro'])
                else:
                    self.ir['services']['mailserver']['volumes'] = ['alias:' + target + ':ro']
                with self.assertRaisesRegex(ValueError, 'alias must remain host read-only'):
                    self.verify()
                self.ir['volumes']['alias'].update(rootlessStrategy='shared', rootlessAccess='read-only')
                self.verify()
                self.ir['services'].pop('app', None)

    def test_public_and_leaf_reader_policy_is_required(self):
        self.mail()
        for name in ('caddy_ca', 'mail_tls'):
            for field, value in (('rootlessAccess', 'read-write'), ('rootlessStrategy', 'copy')):
                with self.subTest(name=name, field=field):
                    previous = self.ir['volumes'][name][field]
                    self.ir['volumes'][name][field] = value
                    with self.assertRaisesRegex(ValueError, 'host read-only'):
                        self.verify()
                    self.ir['volumes'][name][field] = previous

    def test_only_selected_rootful_or_fixed_uid_rootless_mail_gets_leaf(self):
        for placement in ('rootful', 'rootless'):
            with self.subTest(placement=placement):
                self.mail(placement)
                self.verify()
                self.ir['services']['mailserver']['volumes'] = [
                    {'source': self.scope + '/mail_tls', 'target': '/caddy-mail', 'read_only': True}]
                self.verify()
        self.ir['services']['mailserver']['rootlessDomain'] = 'foreign'
        with self.assertRaisesRegex(ValueError, 'unknown selected domain'):
            self.verify()

    def test_leaf_cannot_be_shared_with_other_apps_or_caddy(self):
        self.mail()
        self.ir['volumes']['leaf_alias'] = {'hostPath': self.scope + '/mail_tls',
            'rootlessStrategy': 'shared', 'rootlessAccess': 'read-only'}
        for source in ('mail_tls', 'leaf_alias', self.scope + '/mail_tls', self.scope + '/mail_tls/current/key.pem'):
            with self.subTest(source=source):
                self.app([source + ':/leaf:ro'])
                with self.assertRaisesRegex(ValueError, 'mail leaf consumer'):
                    self.verify()
        del self.ir['services']['app']
        self.ir['services']['caddy']['volumes'].append('mail_tls:/caddy-mail:ro')
        with self.assertRaisesRegex(ValueError, 'mail leaf consumer'):
            self.verify()

    def test_leaf_write_target_subpath_and_absence_refused(self):
        self.mail()
        for mount in ('mail_tls:/caddy-mail', 'mail_tls:/elsewhere:ro',
                      self.scope + '/mail_tls/current:/caddy-mail:ro', 'mail_tls:/caddy-mail:ro,U'):
            with self.subTest(mount=mount):
                self.ir['services']['mailserver']['volumes'] = [mount]
                with self.assertRaisesRegex(ValueError, 'mail leaf consumer'):
                    self.verify()
        self.ir['services']['mailserver']['volumes'] = []
        with self.assertRaisesRegex(ValueError, 'delegation mount missing'):
            self.verify()

    def test_volume_init_parent_is_not_a_signing_store_exception(self):
        self.ir['services']['volume-init'] = {'placement': 'rootful', 'lifecycle': 'oneshot',
                                            'volumes': [self.scope + ':/all:rw']}
        with self.assertRaisesRegex(ValueError, 'signing store consumer'):
            self.verify()

    def test_noncanonical_control_lanes_and_named_aliases_refused(self):
        for source in ('/run/./p0-control', '/run/a/../p0-control', '//run/p0-control',
                       '/run//p0-control', '/run/p0-control/', '/var/run/p0-control',
                       '/run/p0-control/http.sock', '/run', '/run/platform-zero',
                       '/run/p0-lanes/dispatch.sock', '/var/lib/platform-zero',
                       '/tmp/worklanes/socket', '/tmp/.worklane/lane.toml', '/proc/1/root/run/p0-control'):
            with self.subTest(source=source):
                self.app([source + ':/control:ro'])
                with self.assertRaises(ValueError):
                    self.verify()
        self.ir['volumes']['socket_alias'] = {'hostPath': '/run/p0-control'}
        self.app(['socket_alias:/control:ro'])
        with self.assertRaisesRegex(ValueError, 'storage scope'):
            self.verify()

    def test_noncanonical_trust_and_unresolved_sources_refused(self):
        for source in (self.scope + '/caddy_ca/../caddy_certs', self.scope + '//caddy_certs',
                       './configs/../../run/p0-control', '${PRIVATE_ROOT}/certs', 'undeclared',
                       '%t/../p0-control', '/proc/1/root/tmp/certs', '/dev/fd/4'):
            with self.subTest(source=source):
                self.app([source + ':/keys:ro'])
                with self.assertRaises(ValueError):
                    self.verify()
        self.ir['volumes']['caddy_certs']['hostPath'] = self.scope + '/./caddy_certs'
        with self.assertRaisesRegex(ValueError, 'noncanonical'):
            self.verify()

    def test_malformed_mounts_are_not_coerced(self):
        for mount in (None, {}, {'source': 'caddy_ca', 'target': '/ca', 'read_only': 'true'},
                      {'source': 'caddy_ca', 'target': '/ca', 'read_only': True, 'bind': {}},
                      'caddy_ca', 'caddy_ca:/ca:ro:rw', 'caddy_ca:/ca:ro,rw', 'caddy_ca:/ca:ro,ro',
                      'caddy_ca:/ca:ro,unknown', ':/ca:ro'):
            with self.subTest(mount=mount):
                self.app([mount])
                with self.assertRaises(ValueError):
                    self.verify()

    def test_no_host_bind_sources_are_opened(self):
        # Bind roots need not exist; proof is only sealed source admission.
        self.app([self.scope + '/caddy_ca/caddy-ca.crt:/ca:ro'])
        original = os.open
        allowed = {'/', *self.root.parts[1:], 'site', 'manifest.json', 'stack.ir.json',
                   'podman-domains.json', 'source-provenance.json', 'bundle.json'}
        def only_bundle(path, *args, **kwargs):
            self.assertIn(str(path), allowed, 'attempt to open a non-bundle/host mount input')
            return original(path, *args, **kwargs)
        with patch.object(verifier.os, 'open', side_effect=only_bundle):
            self.verify()

    def test_input_hardlinks_final_and_ancestor_symlinks_refused(self):
        self.fixture.seal()
        manifest = self.root / 'site/manifest.json'
        hardlink = self.root / 'manifest-hardlink'
        os.link(manifest, hardlink)
        with self.assertRaisesRegex(ValueError, 'linked'):
            verifier.verify(self.root)
        hardlink.unlink()
        original = self.root / 'saved-manifest'
        manifest.rename(original); manifest.symlink_to(original)
        with self.assertRaisesRegex(ValueError, 'linked'):
            verifier.verify(self.root)
        manifest.unlink(); original.rename(manifest)
        site = self.root / 'site'; saved = self.root / 'saved-site'
        site.rename(saved); site.symlink_to(saved, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'linked'):
            verifier.verify(self.root)

    def test_missing_wildcard_prefix_or_foreign_unit_scope_refused(self):
        self.alloy()
        environment = self.ir['services']['alloy']['environment']
        for value in (None, '.*', 'webservices-.*', '(webservices[-.][^;]*;.*|[^;]*;webservices[-.].*)',
                      '^(webservices-sshd[.]service;)$',
                      '^(webservices-alloy[.]service;|webservices-caddy[.]service;|webservices-foreign[.]service;)$'):
            with self.subTest(regex=value):
                environment['STACK_LOG_UNIT_REGEX'] = value
                with self.assertRaisesRegex(ValueError, 'journal unit scope'):
                    self.verify()

    def test_exact_uid_and_system_user_unit_pair_scope(self):
        self.alloy(); self.app([])
        expected = ('^(webservices-alloy[.]service;|user@42[.]service;webservices-app[.]service|'
                    'webservices-caddy[.]service;)$')
        environment = self.ir['services']['alloy']['environment']
        environment['STACK_LOG_UNIT_REGEX'] = expected
        self.verify()
        for pair in ('webservices-caddy.service;', 'webservices-alloy.service;',
                     'user@42.service;webservices-app.service'):
            self.assertIsNotNone(re.fullmatch(expected, pair))
        for pair in ('sshd.service;', 'webservices-foreign.service;', 'p0-lanes.service;',
                     'user@99.service;webservices-app.service',
                     'foreign.service;webservices-app.service',
                     'webservices-caddyXservice;', 'webservices-caddy.service;foreign.service'):
            self.assertIsNone(re.fullmatch(expected, pair))
        for uid in ('42', '0', '0|42|99', '.*', '${STACK_LOG_UID_REGEX}', '42|0'):
            environment['STACK_LOG_UID_REGEX'] = uid
            with self.assertRaisesRegex(ValueError, 'journal UID scope'):
                self.verify()

    def test_finance_and_shared_postgres_remain_outside_unit_allowlist(self):
        self.alloy()
        self.ir['services']['firefly'] = {'placement': 'rootless', 'rootlessDomain': 'apps'}
        self.ir['services']['postgres'] = {'placement': 'rootful'}
        expected = self.ir['services']['alloy']['environment']['STACK_LOG_UNIT_REGEX']
        self.verify()
        for pair in ('user@42.service;webservices-firefly.service', 'webservices-postgres.service;'):
            self.assertIsNone(re.fullmatch(expected, pair))
        self.ir['services']['alloy']['environment']['STACK_LOG_UNIT_REGEX'] = expected[:-2] + '|webservices-postgres[.]service;)$'
        with self.assertRaisesRegex(ValueError, 'journal unit scope'):
            self.verify()

    def test_invalid_selected_identity_or_service_cannot_expand_scope(self):
        self.alloy()
        for row in ({'name': 'apps', 'uid': True}, {'name': 'rootful', 'uid': 42},
                    {'name': 'apps|foreign', 'uid': 42}, {'name': 'apps', 'uid': 0}):
            with self.subTest(row=row):
                self.domains['domains'] = [row]
                with self.assertRaisesRegex(ValueError, 'journal UID scope'):
                    self.verify()
        self.domains['domains'] = [{'name': 'apps', 'uid': 42}]
        self.ir['services']['foreign.*'] = {}
        with self.assertRaisesRegex(ValueError, 'invalid selected service'):
            self.verify()

    def test_exact_scope_changes_require_new_unit_scope(self):
        self.alloy(); self.verify()
        self.ir['services']['new-selected-service'] = {'placement': 'rootful'}
        with self.assertRaisesRegex(ValueError, 'journal unit scope'):
            self.verify()


if __name__ == '__main__':
    unittest.main()
