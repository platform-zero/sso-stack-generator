#!/usr/bin/env python3
"""Network=none is allowed only in exactly four no-pull build Quadlets."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
src=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/verify-existing-host-venue.py'
spec=importlib.util.spec_from_file_location('venue_network_screen',src)
screen=importlib.util.module_from_spec(spec);spec.loader.exec_module(screen)

class OfflineBuildNetwork(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.root=Path(t.name);d=self.root/'quadlet/rootless-apps';d.mkdir(parents=True)
        self.build=d/'p0test-r1-mastodon-rss-publisher.build'
        self.build.write_text('[Build]\nPull=never\nNetwork=none\n')
        self.selector={'unitPrefix':'p0test-r1'}
    def test_all_four_selected_no_pull_builds_accept_offline_network(self):
        self.build.unlink()
        for producer in ('keycloak','onboarding','mastodon-rss-publisher','firefly-native-api'):
            path=self.build.parent/('p0test-r1-'+producer+'.build')
            path.write_text('[Build]\nPull=never\nNetwork=none\n')
        self.assertEqual(screen.screen_quadlet_names(self.root,self.selector),4)
    def test_only_selected_no_pull_build_may_use_offline_network(self):
        self.assertEqual(screen.screen_quadlet_names(self.root,self.selector),1)
        self.build.write_text('[Build]\nNetwork=none\n')
        with self.assertRaisesRegex(screen.Refusal,'network reference collides'):
            screen.screen_quadlet_names(self.root,self.selector)
        self.build.write_text('[Build]\nPull=never\nNetwork=none\n')
        foreign=self.build.parent/'p0test-r1-foreign.build';foreign.write_text('[Build]\nPull=never\nNetwork=none\n')
        with self.assertRaisesRegex(screen.Refusal,'network reference collides'):
            screen.screen_quadlet_names(self.root,self.selector)
        foreign.unlink()
        foreign=self.build.parent/'p0test-r1-app.container';foreign.write_text('[Container]\nNetwork=none\n')
        with self.assertRaisesRegex(screen.Refusal,'network reference collides'):
            screen.screen_quadlet_names(self.root,self.selector)

if __name__=='__main__':unittest.main()
