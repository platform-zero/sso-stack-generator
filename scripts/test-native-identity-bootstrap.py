#!/usr/bin/env python3
"""Run the real installer identity function against shell stubs, never host accounts."""
from pathlib import Path
import subprocess
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/install-podman-bundle.sh'
TEXT = SOURCE.read_text()
FUNCTION = TEXT[TEXT.index('ensure_rootless_domain() {'):TEXT.index('\nuser_systemctl() {')]

STUBS = r'''
set -euo pipefail
STANDALONE=true; BUNDLE=/model/sealed; STATE_ROOT=/model/root
ROOTLESS_DOMAIN_NAMES=(); ROOTLESS_DOMAIN_USERS=(); ROOTLESS_DOMAIN_UIDS=()
ROOTLESS_DOMAIN_SUBUID_STARTS=(); ROOTLESS_DOMAIN_STATE_ROOTS=()
ROOTLESS_DOMAIN_GRAPH_ROOTS=(); ROOTLESS_DOMAIN_VOLUME_ROOTS=()
ROOTLESS_UIDS=(); ROOTLESS_HOMES=()
declare -A FAKE_USERS=() FAKE_GROUPS=()
for ((i=0;i<7;i++)); do
 ROOTLESS_DOMAIN_NAMES+=("domain-$i"); ROOTLESS_DOMAIN_USERS+=("fixture-$i")
 ROOTLESS_DOMAIN_UIDS+=("$((780+i))"); ROOTLESS_DOMAIN_SUBUID_STARTS+=("$((2686976+65536*i))")
 ROOTLESS_DOMAIN_STATE_ROOTS+=("/model/scope/state/domain-$i")
 ROOTLESS_DOMAIN_GRAPH_ROOTS+=("/model/scope/graphs/domain-$i")
 ROOTLESS_DOMAIN_VOLUME_ROOTS+=("/model/scope/volumes/domain-$i")
 if [ "$MODE" != fresh ]; then FAKE_USERS[fixture-$i]=1; FAKE_GROUPS[fixture-$i]=1; fi
done
id() {
 local key="${@: -1}" n="${@: -1}"; n="${n##*-}"
 [[ ${FAKE_USERS[$key]:-0} = 1 ]] || return 1
 case "$1" in
  -u) printf '%s\n' "$((780+n))" ;;
  -g) if [ "$MODE" = wrong-gid ]; then printf '999\n'; else printf '%s\n' "$((780+n))"; fi ;;
 esac
}
getent() {
 local kind="$1" key="$2" n="${2##*-}"
 if [ "$kind" = passwd ]; then
  printf '%s:x:%s:%s::/home/%s:/usr/sbin/nologin\n' "$key" "$((780+n))" "$((780+n))" "$key"
 elif [[ "$key" = fixture-* ]]; then
  if [[ ${FAKE_GROUPS[$key]:-0} = 1 ]]; then printf '%s:x:%s:\n' "$key" "$((780+n))"; else return 2; fi
 else
  if [ "$MODE" = fresh ] && [ "${CONFLICT:-0}" = 1 ]; then printf 'foreign:x:%s:\n' "$key"; else return 2; fi
 fi
}
groupadd() { local key="${@: -1}"; FAKE_GROUPS[$key]=1; printf 'GROUP %s\n' "$key"; }
useradd() { local key="${@: -1}"; FAKE_USERS[$key]=1; printf 'USER %s\n' "$key"; }
grep() { return 0; }
awk() { local arg user=''; for arg in "$@"; do [[ "$arg" = user=* ]] && user="${arg#user=}"; done; printf '%s\n' "$((2686976+65536*${user##*-}))"; }
python3() {
 [ "${#ROOTLESS_UIDS[@]}" = 7 ] || { printf 'EARLY-GATE\n'; return 97; }
 printf 'GATE all=%s\n' "${#ROOTLESS_UIDS[@]}" >&2
 return 73
}
mkdir() { printf 'UNSAFE mkdir\n'; return 98; }
chown() { printf 'UNSAFE chown\n'; return 98; }
chmod() { printf 'UNSAFE chmod\n'; return 98; }
loginctl() { printf 'UNSAFE loginctl\n'; return 98; }
systemctl() { printf 'UNSAFE systemctl\n'; return 98; }
usermod() { printf 'UNSAFE usermod\n'; return 98; }
setfacl() { printf 'UNSAFE setfacl\n'; return 98; }
find() { printf 'UNSAFE find\n'; return 98; }
'''


class IdentityBootstrap(unittest.TestCase):
    def run_model(self, mode='existing', conflict=False):
        script = ('MODE=' + mode + '\nCONFLICT=' + ('1' if conflict else '0') + '\n' + STUBS + '\n' + FUNCTION + r'''
for i in "${!ROOTLESS_DOMAIN_NAMES[@]}"; do ensure_rootless_domain "$i" identity-only; done
printf 'IDENTITIES %s\n' "${ROOTLESS_UIDS[*]}"
ensure_rootless_domain 0
''')
        return subprocess.run(['bash', '-c', script], text=True, capture_output=True, timeout=10)

    def test_all_existing_identities_precede_first_canonical_gate(self):
        result = self.run_model()
        self.assertEqual(result.returncode, 73, result.stderr + result.stdout)
        self.assertIn('IDENTITIES 780 781 782 783 784 785 786', result.stdout)
        self.assertIn('GATE all=7', result.stderr)
        self.assertNotIn('UNSAFE', result.stdout)
        self.assertNotIn('EARLY-GATE', result.stdout)

    def test_fresh_private_primary_groups_are_explicitly_created_before_gates(self):
        result = self.run_model('fresh')
        self.assertEqual(result.returncode, 73, result.stderr + result.stdout)
        self.assertEqual(result.stdout.count('GROUP fixture-'), 7)
        self.assertEqual(result.stdout.count('USER fixture-'), 7)
        self.assertIn('GATE all=7', result.stderr)
        self.assertNotIn('UNSAFE', result.stdout)

    def test_foreign_gid_collision_never_creates_group_or_user(self):
        result = self.run_model('fresh', conflict=True)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertNotIn('GROUP ', result.stdout)
        self.assertNotIn('USER ', result.stdout)
        self.assertNotIn('GATE', result.stdout)

    def test_existing_wrong_primary_gid_refuses_before_scope_or_runtime(self):
        result = self.run_model('wrong-gid')
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertNotIn('GATE', result.stdout)
        self.assertNotIn('UNSAFE', result.stdout)

    def test_canonical_script_calls_identity_pass_before_full_domain_setup(self):
        start = TEXT.index('chmod 0700 "$STATE_ROOT/runtime-env"')
        identity = TEXT.index('ensure_rootless_domain "$i" identity-only', start)
        full = TEXT.index('ensure_rootless_domain "$i"\n', start)
        self.assertLess(identity, full)
        self.assertLess(full, TEXT.index('cp -a "$BUNDLE/." "$release/"'))


if __name__ == '__main__':
    unittest.main()
