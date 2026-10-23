#!/usr/bin/env python3
"""Source-only pin-label conversion; no runtime/account/image operations."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('rebind', Path(__file__).parent / 'rebind-image-authorities.py')
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)


def policy(app='old-apps', db='old-platform'):
    return {'podman': {'domains': {'apps': {'user': app}, 'platform': {'user': db}}}}


class Rebind(unittest.TestCase):
    def test_registry_config_ids_and_references_preserved(self):
        pins = {'old-apps|registry.example/app@sha256:' + 'a' * 64: 'sha256:' + 'b' * 64,
                'root|registry.example/edge@sha256:' + 'c' * 64: 'sha256:' + 'd' * 64}
        result = M.rebind(pins, policy(), policy('new-apps', 'new-platform'))
        self.assertEqual(sorted(result.values()), sorted(pins.values()))
        self.assertEqual(result['new-apps|registry.example/app@sha256:' + 'a' * 64], 'sha256:' + 'b' * 64)
        self.assertIn('root|registry.example/edge@sha256:' + 'c' * 64, result)
        self.assertIn('old-apps|registry.example/app@sha256:' + 'a' * 64, pins)

    def test_base_metadata_preserved_without_identity_mutation(self):
        data = {'schemaVersion': 1, 'platform': 'linux/amd64', 'baseImages': {
            'old-apps|registry.example/base:release': {'configId': 'sha256:' + 'a' * 64,
                                                      'registryReference': 'registry.example/base:release',
                                                      'linuxAmd64ManifestDigest': 'sha256:' + 'b' * 64}}}
        result = M.rebind(data, policy(), policy('new-apps', 'new-platform'))
        self.assertEqual(result['baseImages']['new-apps|registry.example/base:release'],
                         data['baseImages']['old-apps|registry.example/base:release'])
        self.assertEqual(result['platform'], data['platform'])

    def test_unknown_authority_refused(self):
        with self.assertRaisesRegex(ValueError, 'unknown'):
            M.rebind({'unrelated|image': 'sha256:' + 'a' * 64}, policy(), policy('new-apps', 'new-platform'))

    def test_domain_membership_change_refused(self):
        after = policy('new-apps', 'new-platform'); del after['podman']['domains']['platform']
        with self.assertRaisesRegex(ValueError, 'membership'):
            M.rebind({'old-apps|image': 'sha256:' + 'a' * 64}, policy(), after)

    def test_duplicate_accounts_or_mutable_identity_refused(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            M.rebind({'old-apps|image': 'sha256:' + 'a' * 64}, policy(), policy('collision', 'collision'))
        with self.assertRaisesRegex(ValueError, 'immutable'):
            M.rebind({'old-apps|image': 'latest'}, policy(), policy('new-apps', 'new-platform'))


if __name__ == '__main__': unittest.main()
