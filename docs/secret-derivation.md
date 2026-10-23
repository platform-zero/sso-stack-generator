# Independent secret derivation

## Input contract

`STACK_DERIVATION_KEY` is a **root-only derivation input**, not a service
credential. Provision it as a JSON string in the explicitly selected encrypted
SOPS store. Its format is exactly 64 hexadecimal characters encoding 32 bytes
of independently generated cryptographic randomness. Hexadecimal case does not
change the key bytes. Do not derive it from, copy it from, or share it with an
owner password, service authentication token, OAuth client secret, or any other
service value. Direct equality with another render value (including hex case
variants) is refused, but source code cannot prove independent generation.

The library reads this field only from `RENDER_VALUES`, normally populated by
`load_secret_store`. It does not read a shell environment variable, discover a
key file, decrypt a new store, generate a replacement key, or rotate credentials.
The existing renderer must load the encrypted store through its authorized
boundary. If a required value is absent or empty and no valid independent key
is available, rendering fails. Service/client/owner secrets and the empty
string are never fallback seeds. If **all** required credentials are explicitly
provided, the derivation key is unnecessary.

The key must remain encrypted at rest and only be decrypted in the existing
root-authorized renderer/installer boundary. It must not be placed in site
configuration, CLI arguments, environment variables, build outputs, logs,
receipts, service configuration, service env shards, or service-readable files.
Shell tracing must be disabled before loading or supplying secrets; the loader,
derivation, and projection entrypoints refuse tracing. Do not enable tracing on
callers that already hold credentials.

## Algorithm and encodings

For a domain `D` and secret label `L`, both UTF-8 strings, the raw result is:

```text
HMAC-SHA256(
  key = hex_decode(STACK_DERIVATION_KEY),
  message = "webservices/secret-derivation/v1" || NUL || D || NUL || L
)
```

The requested 1..64 leading lowercase hexadecimal characters form the usual
secret. NUL-separated inputs prevent domain/label concatenation ambiguity;
Bash render values cannot contain NUL. Key input travels to the Python standard
library helper through stdin, not process arguments or exported variables.
Distinct labels separate identity, database, session, and other service
credentials. Changing the root key, domain, label, or algorithm changes missing
values and must be treated as a credential rotation, never as a routine upgrade.

Special encodings retain their existing service formats:

- Laravel/BookStack: `base64:` followed by unpadded standard base64 of the full
  32 derived bytes. Existing padded or unpadded app keys are preserved.
- Airflow Fernet: URL-safe padded base64 of 32 bytes derived with the
  `airflow-fernet` label. This replaces random generation only for missing keys;
  an existing explicit Fernet key is never regenerated.
- OpenSearch: `Aa1!` plus the requested remaining hexadecimal characters (32
  characters total for the default password).
- Environment output retains its existing dollar escaping; explicit secret
  bytes in the render map are not normalized or re-encoded.

Nonempty explicit credentials win unchanged. Invalid explicit Laravel app keys
or OpenSearch policy passwords now fail instead of being silently replaced.
LDAP SSHA still hashes the explicitly supplied owner password using its existing
random salt; an absent owner password is not hashed as an empty password. An
explicit `ADMIN_SSHA_PASSWORD` may supply that value instead. Owner bootstrap
and required-action integration belong to the existing deployment renderer,
not this derivation helper.

## Projection and installer integration requirements

The library's `write_env_file` excludes `STACK_DERIVATION_KEY` for both selected
and all-values/debug projections, and `render_envsubst` refuses the key as a
template input. Both reject direct key reuse under another render name before
projection. The root key remains only in the private render map while rendering.

**Other projection paths must also blacklist `STACK_DERIVATION_KEY`**, including
root-to-service/actor shards, arbitrary template renderers, diagnostic dumps,
serialized render maps, native installer projections, and test-runner envs.
A service allowlist must not override that blacklist. Reject attempted template
references to the key; do not silently turn them into an accepted empty secret.
No service should receive the encrypted root store or its decryption authority.

File ownership, no-follow/no-hardlink/path-containment checks, selected scope,
marker/receipt/hash/CAS binding, and journalled installer authority remain with
the existing input and projection boundary. This library takes an in-memory
map: it does **not** establish or prove those filesystem/privilege properties.
Do not use it to bypass them. The isolated tests do not prove deployed root-only
storage or service separation.

For an existing installation, preserve all current independent credentials as
explicit encrypted values before adopting this policy. Do not backfill or
silently rotate live values using the new algorithm. This source change performs
no live read, provisioning, migration, or rotation. Legacy test fixtures that
rely on fallback derivation need a synthetic independent key or a complete set
of explicit synthetic credentials.

## Matrix legacy OIDC: separate unresolved policy

The legacy `SYNAPSE_LEGACY_SSO_CONFIG` source is unchanged. In particular it
currently emits `discover: false`, `skip_verification: true`, an external HTTPS
issuer/authorization URL, internal HTTP token/userinfo/JWKS endpoints at
`keycloak:8080`, and `allow_existing_users: true`. Preserving those settings is
not evidence that legacy OIDC is secure, supported, or verified.

Separate integration dependencies are:

1. Select and implement the intended TLS/trust topology for Synapse-to-Keycloak
   token, userinfo, and JWKS requests. If verified HTTPS is required, provide
   usable routing, hostname validation, and CA trust at the selected issuer;
   validate issuer/metadata behavior before changing `skip_verification` or
   discovery settings. No CA/hostname verification bypass is an acceptance fix.
2. Decide the existing-account-link policy explicitly before changing
   `allow_existing_users`. The current mapping derives localpart from
   `preferred_username` (falling back to `sub`), lowercased. Validate collision,
   existing-account ownership, and authorized linking behavior against the
   selected Synapse/Keycloak versions and policy; a blanket rewrite is not proof.
3. Prove the real legacy login/callback, mapped account, logout behavior, and
   encrypted client-secret delivery in an authorized deployed test. The MAS
   branch clears legacy config when active and requires its own separate proof.

Neither deployed legacy OIDC nor these TLS/account-link policy decisions have
been tested or accepted by this isolated source work.

## Isolated test command

```sh
python3 -B scripts/test-independent-secret-derivation.py
```

The suite copies only the three owning library sources into disposable roots
inside the repository, supplies a fixed clean subprocess environment and public
synthetic inputs, and uses no decrypt, host installation, network, container,
service-manager, or JVM operations. It covers refusal, deterministic separation,
explicit-value preservation, secret encodings, failure propagation, key
projection/logging guards, and unchanged Matrix legacy source policy. It is
source/synthetic proof only, not installation or real-owner acceptance.
