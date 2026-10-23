#!/usr/bin/env python3
"""Synthetic source-library tests: no SOPS, network, host install, or ambient env."""

import base64
import hashlib
import hmac
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
# Public synthetic fixtures, not installation inputs or existing credentials.
KEY = "a4" * 32
OTHER_KEY = "b5" * 32
DOMAIN = "derivation.example.test"


def assignments(values):
    return "\n".join(
        f"render_set {name} {shlex.quote(value)}" for name, value in values.items()
    )


def expected(label, length=48, domain=DOMAIN, key=KEY):
    message = b"webservices/secret-derivation/v1\0" + domain.encode() + b"\0" + label.encode()
    return hmac.new(bytes.fromhex(key), message, hashlib.sha256).hexdigest()[:length]


class IndependentSecretDerivation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix=".secret-derivation-test-", dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.lib = self.root / "scripts/lib/render-values.sh"
        self.lib.parent.mkdir(parents=True)
        for name in ("render-values.sh", "common.sh", "site-manifest.sh"):
            (self.lib.parent / name).write_bytes((ROOT / "scripts/lib" / name).read_bytes())
        (self.root / "home").mkdir()
        self.env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.root / "home"),
            "TMPDIR": str(self.root),
            "XDG_STATE_HOME": str(self.root / "state"),
            "LC_ALL": "C.UTF-8",
        }

    def shell(self, body, values=None, success=True, strict=True):
        script = (
            ("set -euo pipefail\n" if strict else "set -uo pipefail\n")
            + 'source "$1"\n'
            + assignments(values or {})
            + "\n"
            + body
        )
        result = subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-s", "--", str(self.lib)],
            input=script,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.env,
            cwd=self.root,
            timeout=20,
        )
        self.assertNotIn(KEY, result.stdout + result.stderr, "root key leaked into output")
        self.assertNotIn(OTHER_KEY, result.stdout + result.stderr, "root key leaked into output")
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result

    def base(self, **values):
        return {"DOMAIN": DOMAIN, "STACK_DERIVATION_KEY": KEY, **values}

    def snapshot(self):
        result = self.shell(
            "build_derived_render_values\n"
            'for key in "${!RENDER_VALUES[@]}"; do\n'
            '  [ "$key" = STACK_DERIVATION_KEY ] || printf "%s\\0%s\\0" "$key" "${RENDER_VALUES[$key]}"\n'
            "done\n",
            self.base(CADDY_TLS_MODE="local", STACK_ADMIN_PASSWORD="Synthetic-Owner-Only!"),
        )
        parts = result.stdout.split("\0")
        self.assertEqual(parts.pop(), "")
        return dict(zip(parts[::2], parts[1::2]))

    def test_empty_or_absent_seed_fails_without_output(self):
        for root_key in (None, "", "short", "g" * 64, "a" * 63, "a" * 65):
            with self.subTest(root_key=root_key):
                values = {"DOMAIN": DOMAIN}
                if root_key is not None:
                    values["STACK_DERIVATION_KEY"] = root_key
                result = self.shell("derive_stack_secret postgres-admin", values, success=False)
                self.assertEqual(result.stdout, "")
                self.assertIn("independent STACK_DERIVATION_KEY", result.stderr)

    def test_service_client_and_owner_seeds_cannot_derive_other_secrets(self):
        seeds = {
            "MODEL_CONTEXT_PROXY_AUTH_SECRET": "Synthetic-Service-Seed!",
            "OAUTH2_PROXY_CLIENT_SECRET": "Synthetic-Client-Seed!",
            "STACK_ADMIN_PASSWORD": "Synthetic-Owner-Seed!",
        }
        for name, value in seeds.items():
            with self.subTest(seed=name):
                result = self.shell(
                    "derive_if_missing POSTGRES_ADMIN_PASSWORD postgres-admin",
                    {"DOMAIN": DOMAIN, name: value}, success=False,
                )
                self.assertEqual(result.stdout, "")
                self.assertNotIn(value, result.stderr)
        self.shell("derive_stack_secret synapse-macaroon", {"DOMAIN": DOMAIN, **seeds}, success=False)

    def test_ambient_environment_is_not_a_derivation_input(self):
        self.env["STACK_DERIVATION_KEY"] = KEY
        self.shell("derive_stack_secret postgres-admin", {"DOMAIN": DOMAIN}, success=False)

    def test_direct_root_reuse_is_refused(self):
        for value in (KEY, KEY.upper()):
            result = self.shell(
                "derive_stack_secret keycloak-admin",
                self.base(MODEL_CONTEXT_PROXY_AUTH_SECRET=value), success=False,
            )
            self.assertIn("must not be reused", result.stderr)

    def test_known_vector_domain_label_and_key_separation(self):
        result = self.shell(
            "derive_stack_secret postgres-admin\n"
            "derive_stack_secret keycloak-admin\n"
            "derive_stack_secret synapse-macaroon 64\n",
            self.base(),
        )
        self.assertEqual(result.stdout.splitlines(), [
            expected("postgres-admin"), expected("keycloak-admin"), expected("synapse-macaroon", 64)
        ])
        self.assertEqual(self.shell("derive_stack_secret postgres-admin", self.base()).stdout, result.stdout.splitlines()[0] + "\n")
        for values in (self.base(DOMAIN="other.example.test"), self.base(STACK_DERIVATION_KEY=OTHER_KEY)):
            self.assertNotEqual(self.shell("derive_stack_secret postgres-admin", values).stdout.strip(), expected("postgres-admin"))
        one = self.shell("derive_stack_secret 'b:c'", self.base(DOMAIN="a")).stdout
        two = self.shell("derive_stack_secret c", self.base(DOMAIN="a:b")).stdout
        self.assertNotEqual(one, two)

    def test_service_seed_changes_do_not_change_identity_database_or_session_values(self):
        outputs = []
        for suffix in ("one", "two"):
            values = self.base(**{name: f"Synthetic-{name}-{suffix}" for name in (
                "MODEL_CONTEXT_PROXY_AUTH_SECRET", "OAUTH2_PROXY_CLIENT_SECRET", "STACK_ADMIN_PASSWORD"
            )})
            outputs.append(self.shell(
                "derive_stack_secret keycloak-admin\n"
                "derive_stack_secret postgres-admin\n"
                "derive_stack_secret synapse-macaroon\n", values,
            ).stdout)
        self.assertEqual(outputs[0], outputs[1])

    def test_invalid_domain_label_or_length_fails(self):
        for body, values in (
            ("derive_stack_secret label", self.base(DOMAIN="")),
            ("derive_stack_secret ''", self.base()),
            *((f"derive_stack_secret label {shlex.quote(length)}", self.base()) for length in ("0", "65", "-1", "1+2", "01", "abc")),
        ):
            with self.subTest(body=body):
                self.shell(body, values, success=False)

    def test_explicit_secrets_preserved_byte_for_byte_without_root_key(self):
        value = 'Synthetic $value \\ "quotes" apostrophe\' café\nsecond line'
        result = self.shell(
            "derive_if_missing POSTGRES_ADMIN_PASSWORD postgres-admin\n"
            "render_get POSTGRES_ADMIN_PASSWORD",
            {"POSTGRES_ADMIN_PASSWORD": value},
        )
        self.assertEqual(result.stdout, value)
        snapshot = self.snapshot()
        result = self.shell(
            "build_derived_render_values\n"
            'for key in KEYCLOAK_ADMIN_PASSWORD POSTGRES_ADMIN_PASSWORD SYNAPSE_MACAROON_SECRET BOOKSTACK_APP_KEY AIRFLOW_FERNET_KEY; do\n'
            '  printf "%s\\0" "${RENDER_VALUES[$key]}"\n'
            "done\n", snapshot,
        )
        self.assertEqual(result.stdout.split("\0")[:-1], [snapshot[k] for k in (
            "KEYCLOAK_ADMIN_PASSWORD", "POSTGRES_ADMIN_PASSWORD", "SYNAPSE_MACAROON_SECRET", "BOOKSTACK_APP_KEY", "AIRFLOW_FERNET_KEY"
        )])

    def test_failure_propagates_without_errexit_and_never_sets_missing_value(self):
        result = self.shell(
            "if derive_if_missing POSTGRES_ADMIN_PASSWORD postgres-admin; then exit 91; fi\n"
            "if render_has POSTGRES_ADMIN_PASSWORD; then exit 92; fi\n"
            "printf 'refused'\n", {"DOMAIN": DOMAIN}, strict=False,
        )
        self.assertEqual(result.stdout, "refused")
        snapshot = self.snapshot()
        # Exercise failures in early, middle, encoded, policy and late paths.
        for missing in ("MODEL_CONTEXT_PROXY_AUTH_SECRET", "KEYCLOAK_ADMIN_PASSWORD", "POSTGRES_ADMIN_PASSWORD", "OAUTH2_PROXY_COOKIE_SECRET", "BOOKSTACK_APP_KEY", "OPENSEARCH_ADMIN_PASSWORD", "AIRFLOW_FERNET_KEY", "GPU_ARBITER_API_TOKEN", "MATRIX_AUTHENTICATION_SERVICE_ENCRYPTION_SECRET"):
            with self.subTest(missing=missing):
                values = {k: v for k, v in snapshot.items() if k != missing}
                result = self.shell(
                    "if build_derived_render_values; then exit 91; fi\n"
                    f"if render_has {missing}; then exit 92; fi\n"
                    "printf 'refused'\n", values, strict=False,
                )
                self.assertEqual(result.stdout, "refused")

    def test_encoding_and_policy_are_stable_and_explicit_values_are_not_rotated(self):
        result = self.shell(
            "derive_laravel_app_key_if_missing BOOKSTACK_APP_KEY bookstack-app-key\n"
            "derive_fernet_key_if_missing\n"
            "render_get BOOKSTACK_APP_KEY; printf '\\n'\n"
            "render_get AIRFLOW_FERNET_KEY; printf '\\n'\n"
            "derive_policy_secret opensearch-admin 32\n", self.base(),
        )
        laravel, fernet, policy = result.stdout.splitlines()
        self.assertEqual(laravel, "base64:" + base64.b64encode(bytes.fromhex(expected("bookstack-app-key", 64))).decode().rstrip("="))
        self.assertEqual(fernet, base64.urlsafe_b64encode(bytes.fromhex(expected("airflow-fernet", 64))).decode())
        self.assertEqual(len(base64.urlsafe_b64decode(fernet)), 32)
        self.assertEqual(policy, "Aa1!" + expected("opensearch-admin", 28))
        self.assertEqual(len(policy), 32)
        for explicit in (laravel, laravel + "="):
            self.assertEqual(self.shell(
                "derive_laravel_app_key_if_missing BOOKSTACK_APP_KEY bookstack-app-key\nrender_get BOOKSTACK_APP_KEY",
                {"BOOKSTACK_APP_KEY": explicit},
            ).stdout, explicit)
        self.assertEqual(self.shell("derive_fernet_key_if_missing\nrender_get AIRFLOW_FERNET_KEY", {"AIRFLOW_FERNET_KEY": fernet}).stdout, fernet)
        self.shell("derive_laravel_app_key_if_missing BOOKSTACK_APP_KEY bookstack-app-key", self.base(BOOKSTACK_APP_KEY="invalid-explicit"), success=False)
        snapshot = self.snapshot()
        snapshot["OPENSEARCH_ADMIN_PASSWORD"] = "invalid-explicit"
        self.shell("build_derived_render_values", snapshot, success=False)

    def test_empty_owner_password_is_not_hashed(self):
        self.shell("build_derived_render_values", self.base(CADDY_TLS_MODE="local"), success=False)

    def test_no_key_in_logs_arguments_or_exported_environment(self):
        result = self.shell(
            "python3() {\n"
            '  case "$*" in *"${RENDER_VALUES[STACK_DERIVATION_KEY]}"*) return 93;; esac\n'
            '  [ "${STACK_DERIVATION_KEY+x}" != x ] || return 94\n'
            '  command python3 "$@"\n'
            "}\n"
            "derive_if_missing POSTGRES_ADMIN_PASSWORD postgres-admin\n",
            self.base(),
        )
        self.assertEqual(result.stdout + result.stderr, "")
        result = self.shell("set -x\nderive_stack_secret postgres-admin", self.base(), success=False)
        self.assertIn("refuses shell tracing", result.stderr)

    def test_key_is_blacklisted_from_all_and_selected_env_projection(self):
        value = 'Synthetic$value\\literal"quote'
        self.shell(
            "write_env_file all.env\n"
            "write_env_file selected.env STACK_DERIVATION_KEY POSTGRES_ADMIN_PASSWORD\n",
            self.base(POSTGRES_ADMIN_PASSWORD=value),
        )
        for name in ("all.env", "selected.env"):
            path = self.root / name
            text = path.read_text()
            self.assertNotIn("STACK_DERIVATION_KEY", text)
            self.assertNotIn(KEY, text)
            self.assertIn("POSTGRES_ADMIN_PASSWORD=" + value.replace("$", "$$"), text)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_direct_key_alias_is_refused_before_projection_writes(self):
        values = self.base(POSTGRES_ADMIN_PASSWORD=KEY)
        self.shell("write_env_file alias.env POSTGRES_ADMIN_PASSWORD", values, success=False)
        self.assertFalse((self.root / "alias.env").exists())
        self.shell("render_envsubst '${POSTGRES_ADMIN_PASSWORD}' POSTGRES_ADMIN_PASSWORD", values, success=False)
        snapshot = self.snapshot()
        snapshot.update(values)
        self.shell("build_derived_render_values", snapshot, success=False)

    def test_key_is_not_available_to_template_export(self):
        result = self.shell(
            "envsubst() {\n"
            '  [ "${STACK_DERIVATION_KEY+x}" != x ] || return 95\n'
            "  printf 'template-ok'\n"
            "}\n"
            "render_envsubst '${DOMAIN}' DOMAIN\n", self.base(),
        )
        self.assertEqual(result.stdout, "template-ok")
        for selector, keys in (("${STACK_DERIVATION_KEY}", "STACK_DERIVATION_KEY"), ("${STACK_DERIVATION_KEY}", "DOMAIN"), ("$STACK_DERIVATION_KEY", "DOMAIN")):
            self.shell(f"render_envsubst {shlex.quote(selector)} {keys}", self.base(), success=False)

    def test_full_build_is_repeatable_for_required_secrets(self):
        one, two = self.snapshot(), self.snapshot()
        secret_keys = [k for k in one if re.search(r"PASSWORD|SECRET|TOKEN|APP_KEY|FERNET_KEY|API_KEY", k) and k != "ADMIN_SSHA_PASSWORD"]
        self.assertGreater(len(secret_keys), 65)
        for key in secret_keys:
            with self.subTest(key=key):
                self.assertEqual(one[key], two[key])
        self.assertEqual(one["KEYCLOAK_ADMIN_PASSWORD"], expected("keycloak-admin"))
        self.assertEqual(one["POSTGRES_ADMIN_PASSWORD"], expected("postgres-admin"))
        self.assertEqual(one["SYNAPSE_MACAROON_SECRET"], expected("synapse-macaroon"))

    def test_matrix_legacy_policy_is_not_silently_rewritten(self):
        source = self.lib.read_text()
        for line in ("    skip_verification: true", "    allow_existing_users: true", "    token_endpoint: \"http://keycloak:8080/", "    jwks_uri: \"http://keycloak:8080/"):
            self.assertIn(line, source)
        # This is a source preservation check, NOT TLS, account-linking or OIDC proof.


if __name__ == "__main__":
    unittest.main(verbosity=2)
