#!/usr/bin/env python3
"""Owning shell function tests with exact selection and command stubs only."""
from pathlib import Path
import subprocess
import unittest

TEXT=(Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/install-podman-bundle.sh').read_text()
BUILDS=TEXT[TEXT.index('native_selected_units() {'):TEXT.index('\ncancel_webservices_start_jobs() {')]
NETWORKS=TEXT[TEXT.index('restart_rootful_network_units() {'):TEXT.index('\nwait_for_cross_domain_producers() {')]
START=TEXT.index('  native_rootful_services="$(native_selected_units rootful 0 services)"')
EARLY=TEXT[TEXT.rfind('if [ "$STANDALONE" = true ]; then',0,START):TEXT.index('\nfor i in "${!ROOTLESS_DOMAIN_NAMES[@]}"; do\n  user_systemctl "$i" daemon-reload',START)]


class SelectedActivation(unittest.TestCase):
    def model(self,command,*,services='',builds='',networks='',refuse=False,early_done=False):
        script='set -euo pipefail\nSTANDALONE=true\nrelease=/model/sealed\nROOTLESS_DOMAIN_NAMES=(platform apps)\n'+BUILDS+'\n'+NETWORKS+r'''
native_selected_units() {
 printf 'SELECT %s %s %s\n' "$1" "$2" "$3" >&2
 [ "$REFUSE" = false ] || return 43
 case "$3" in services) printf '%s\n' "$SERVICES";; builds) printf '%s\n' "$BUILDS";; networks) printf '%s\n' "$NETWORKS";; *) return 99;; esac
}
systemctl() { printf 'ROOT %s\n' "$*"; }
user_systemctl() { printf 'ACTOR %s\n' "$*"; }
python3() { printf 'TRUST %s\n' "$*"; }
find() { printf 'FORBIDDEN source scan\n'; return 98; }
'''
        import os
        env=dict(os.environ,SERVICES=services,BUILDS=builds,NETWORKS=networks,REFUSE=str(refuse).lower())
        if early_done: script+='\nCADDY_EARLY_BUILD_COMPLETE=true\n'
        return subprocess.run(['bash','-c',script+'\n'+command],env=env,text=True,capture_output=True,timeout=10)

    def test_selected_build_names_not_source_directory_scan(self):
        result=self.model('build_selected_serially rootless 1 /model/untrusted',builds='webservices-new-build.service')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('ACTOR 1 restart webservices-new-build.service',result.stdout)
        self.assertNotIn('FORBIDDEN',result.stdout)
        self.assertIn('SELECT rootless 1 builds',result.stderr)

    def test_builder_refusal_is_not_swallowed_by_process_substitution(self):
        result=self.model('build_selected_serially rootful 0 /model/untrusted',refuse=True)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('ROOT ',result.stdout)

    def test_early_completed_caddy_builder_not_repeated(self):
        result=self.model('build_selected_serially rootful 0 /model/untrusted',
                          builds='webservices-caddy-build.service\nwebservices-mail-build.service',early_done=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('restart webservices-caddy-build.service',result.stdout)
        self.assertIn('restart webservices-mail-build.service',result.stdout)

    def test_candidate_networks_only_in_correct_actor_scope(self):
        result=self.model('restart_rootless_network_units 1',networks='webservices-exact-network.service')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('ACTOR 1 restart webservices-exact-network.service',result.stdout)
        self.assertIn('SELECT rootless 1 networks',result.stderr)

    def test_empty_network_selection_has_no_manager_action(self):
        result=self.model('restart_rootful_network_units')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('ROOT ',result.stdout)

    def test_network_selection_refusal_prevents_restart(self):
        result=self.model('restart_rootful_network_units',refuse=True)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('ROOT ',result.stdout)

    def test_candidate_caddy_builder_precedes_early_service(self):
        result=self.model(EARLY,services='webservices-caddy.service',builds='webservices-caddy-build.service')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertLess(result.stdout.index('restart webservices-caddy-build.service'),result.stdout.index('restart webservices-caddy.service'))
        self.assertIn('--publish-mail',result.stdout)

    def test_absent_candidate_caddy_does_not_start_installed_name(self):
        result=self.model(EARLY,services='webservices-mailserver.service')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('ROOT ',result.stdout)
        self.assertNotIn('TRUST ',result.stdout)

    def test_registry_caddy_does_not_invent_builder(self):
        result=self.model(EARLY,services='webservices-caddy.service')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('ROOT restart webservices-caddy.service',result.stdout)
        self.assertNotIn('restart webservices-caddy-build.service',result.stdout)


if __name__=='__main__': unittest.main()
