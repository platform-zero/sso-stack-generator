# Selected host browser/protocol proof

`scripts/verify-host-browser-workflows.py` is an executable acceptance **consumer**,
not an installer, credential provisioner, approval issuer, daemon, or substitute
for the existing serialized operation worker/journal. It implements browser SSO
and narrowly scoped synthetic app round trips. It has not been run against a
host/browser by this source stream. Offline tests are not installed proof;
complete product acceptance remains **0/2** until independently demonstrated.

## Runtime invocation and dependencies

The integration owner must install Python 3, Python Playwright and its compatible
Chromium/system dependencies in the selected test-runner environment. Nothing is
installed by these scripts. Run as the dedicated unprivileged fixture runner;
Chromium sandboxing is mandatory (no root/no-sandbox fallback). The worker must
retain its existing operation authorization/serialization and establish exclusive
use of the selected synthetic fixture before launching this consumer. In
particular Jupyter Contents has no atomic create-if-absent operation: the
`GET 404` / `PUT` sequence is safe only with that external exclusive fixture
lease. `exclusiveFixture: true` is the root publisher's attestation of this
precondition, NOT an authorization or an independently acquired lock.

Example invocation **for the integration owner, not performed by this stream**:

```sh
python3 scripts/verify-host-browser-workflows.py \
  --plan /var/lib/platform-zero/browser-fixture/selection.json \
  --expect-plan-sha256 <sha256-of-exact-selection-bytes> \
  --credentials-fd 3 --timeout 110
```

FD 3 must be opened and inherited by the existing protected launcher. Alternatively
use `--credentials-file /root-controlled-parent/fixture-credentials.json`.
No credentials, passwords, tokens, or cookie values belong in arguments. FD input
must be a regular single-link file owned by root or the effective runner, with
no group/other permissions; pipes are deliberately refused. File input must have
a root-owned, non-writable directory chain and a runner-owned private leaf.

All authority files and every parent directory must be root-owned and not
writable by group/other; every leaf must be regular, single-link, <=256 KiB.
Symlinks, including parent links and `current` aliases, hardlinks, FIFOs, `..`,
empty path components and relative paths are refused. This includes the plan,
fixture marker, existing install journal and release receipt. The unprivileged
runner needs narrowly granted **read-only** access to those exact root files;
the script does not change their permissions or copy/read encrypted stores.
No source hash, journal hash or marker should be guessed from a different release.
The existing worker must also validate its selected harness executable as usual.

Provision normal DNS and trusted HTTPS certificates for the selected hostnames.
There is no IP override, custom resolver, TLS bypass, alternative port, client
certificate or password-grant mode. Browser HTTP requests are allowlisted to the
exact Keycloak, portal and declared app origins; protocol requests are pinned to
the selected app origin and refuse redirects. This is not an OS egress firewall
or a WebSocket sandbox: keep normal runner network isolation in the launcher.

Use a dedicated disposable runner HOME and private TMPDIR on tmpfs. Playwright
owns temporary Chromium profiles and removes them on normal close. The launcher
owns cleanup after a killed process; this harness does not search/delete caches,
other profiles or application data. Runtime environment is reduced before
Playwright import to PATH, HOME, PLAYWRIGHT_BROWSERS_PATH, TMPDIR, LANG, LC_ALL;
debug/protocol log and proxy variables are not inherited. Do not wrap execution
with shell tracing, record its input FD, attach protocol recording, or enable
external browser/driver logging. The script itself emits no screenshots, traces,
HARs, videos, response bodies, URLs, identifiers, exception strings or secrets.

Per-call timeouts are 7–10 seconds and `--timeout` is bounded to 1–120 seconds.
An alarm cancels further authority/network operations. The existing worker must
also impose its normal hard wall/process-group timeout (<=120 seconds), since
browser/driver teardown after a crash is not a hard real-time operation.

## Protected plan schema (version 1)

The root publisher chooses fresh `runId` (32 lowercase hexadecimal characters),
`fixtureId`, exact selected apps/order, normal URLs, and actual deployed selectors.
The following is a schematic example, not deployable host authority. Hashes and
times must be replaced with exact values; selectors must identify **real app
content**, never fixture placeholder HTML, login panels or setup screens.

```json
{
  "schemaVersion": 1,
  "scope": "host-synthetic-browser",
  "exclusiveFixture": true,
  "runId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "fixtureId": "browser-fixture",
  "issuedAt": 1700000000,
  "expiresAt": 1700000300,
  "stateRoot": "/var/lib/webservices",
  "release": "/var/lib/webservices/releases/SELECTED-RELEASE",
  "selectedApps": ["firefly", "jupyterhub"],
  "marker": {"path": "/var/lib/platform-zero/browser-fixture/marker.json", "sha256": "EXACT_SHA256"},
  "journal": {"path": "/var/lib/webservices/.install-intent.json", "sha256": "EXACT_SHA256"},
  "receipt": {"path": "/var/lib/webservices/releases/SELECTED-RELEASE/installation-receipt.json", "sha256": "EXACT_SHA256"},
  "keycloak": {
    "url": "https://auth.fixture.test",
    "realm": "fixture",
    "logout_url": "https://auth.fixture.test/realms/fixture/account/",
    "logout_selector": "button:has-text('Sign out')"
  },
  "portal": {
    "url": "https://portal.fixture.test/",
    "authenticated_selector": "[data-testid='authenticated-portal']",
    "identity_selector": "[data-testid='account-name']"
  },
  "apps": [
    {
      "id": "firefly",
      "driver": "firefly",
      "url": "https://firefly.fixture.test/",
      "authenticated_selector": "ACTUAL_FIREFLY_AUTHENTICATED_CONTENT",
      "identity_selector": "ACTUAL_FIREFLY_ACCOUNT_IDENTITY",
      "denial": {"url": "https://firefly.fixture.test/", "selector": "ACTUAL_FORBIDDEN_MARKER"}
    },
    {
      "id": "jupyterhub",
      "driver": "jupyterhub",
      "url": "https://jupyter.fixture.test/hub/",
      "server_url": "https://jupyter.fixture.test/user/member/",
      "authenticated_selector": "ACTUAL_HUB_AUTHENTICATED_CONTENT",
      "identity_selector": "ACTUAL_HUB_ACCOUNT_IDENTITY",
      "denial": {"url": "https://jupyter.fixture.test/hub/", "selector": "ACTUAL_FORBIDDEN_MARKER"}
    }
  ]
}
```

The marker is exactly:

```json
{"schemaVersion":1,"scope":"host-synthetic-browser","fixtureId":"browser-fixture","selectedApps":["firefly","jupyterhub"]}
```

This supplemental fixture marker does not replace any installer/machine/operation
marker. The worker still applies those authorities. The existing journal and
receipt must be identical JSON objects, `schemaVersion: 1`, `phase: active`,
matching exact release, with valid installer input pins including `bundle.json`,
`stack.ir.json`, `source-provenance.json`. Their **raw bytes** are separately
hashed. The harness does not open those pinned files or encrypted/runtime stores.
The journal path must be `stateRoot/.install-intent.json`; the release must be a
direct child of `stateRoot/releases`; the receipt must live in that exact release.
The plan/marker/journal/receipt hashes and expiration (maximum 30 minutes) are
rechecked before navigation, credential entry, every API request including cleanup,
and at completion. Changed authority stops affected mutations rather than trying
to acquire new permission. No approval receipt is consumed or recreated here.

Optional app `sso_selector` clicks a real SSO link/button once after navigation;
it never supplies app credentials. App origins must be distinct. Each
`identity_selector` must yield exactly the credential actor's expected identity
after whitespace trimming: optional `identities[appId]` (or `identities.portal`)
first, otherwise `identity`. This supports real apps displaying a username or
email where the portal displays a full name. Login selectors are normal Keycloak `#username`, `#password`,
`#kc-login`; custom themes needing different fields are currently unsupported,
not silently passed. MFA/required-actions fixture accounts must be prepared by
the authorized provisioner, not bypassed here.

## Protected credentials schema

Fields below are placeholders, never literal deploy credentials:

```json
{
  "member": {"username":"FIXTURE_MEMBER", "password":"PROTECTED", "identity":"EXACT_PORTAL_IDENTITY", "identities":{"firefly":"EXACT_FIREFLY_IDENTITY","jupyterhub":"EXACT_HUB_USERNAME"}, "email":"FIXTURE_MEMBER_EMAIL"},
  "denied": {"username":"DISTINCT_DENIED_FIXTURE", "password":"PROTECTED", "identity":"EXACT_VISIBLE_IDENTITY"},
  "firefly": {"firefly":"PROTECTED_MEMBER_PAT"}
}
```

`firefly` maps app ID to pre-provisioned member PAT. Missing PAT/email leaves its
workflow/persistence/cleanup **unproven**, exit 2. The PAT is only for the object
round trip, never shared-login proof: browser SSO must succeed separately, and
`GET /api/v1/about/user` email must match the member before creating an account.
Jupyter uses only the existing browser cookie jar and scoped `_xsrf` cookie.
No native app username/password typing, API token issuance or password grant is
implemented. A Firefly deployment without working native/gateway SSO will fail;
the harness does not paper over missing app support with a PAT login.

## Actual implemented checks and evidence boundaries

| Target | Scope | Observation required |
| --- | --- | --- |
| Keycloak/portal | SSO | Fresh browser redirected to selected realm; normal UI login; portal authenticated marker and exact fixture identity |
| Every selected app | SSO | Same browser context and authenticated fixture identity, no second credential fill, no visible native password form |
| Every selected app | Role denial | Second distinct actor logs in via Keycloak/portal in another context; selected protected URL returns actual HTTP 401/403 with explicit denial marker, no authenticated app marker |
| Portal + selected apps | Logout | Click real Keycloak logout UI, revisit each app in the **existing** member browser context, require Keycloak username/password challenge; surviving native sessions fail |
| Firefly | Workflow | Verify PAT actor; create a uniquely named zero-opening-balance asset account; read back exact returned ID/name/type |
| JupyterHub | Workflow | Navigate already-provisioned fixture user server; require scoped XSRF; GET nonexistent unique notebook, PUT synthetic notebook, read exact content |
| Both implemented apps | Persistence | Reload browser page and read back same app object; **not** restart, durable-storage, backup or crash recovery proof |
| Both implemented apps | Cleanup | Recheck authority and exact created object, delete only it, require subsequent 404 |
| Every selected target | Transport/readiness | Successful TLS/HTTP separately from authenticated app content; HTTP 5xx is transport observed but readiness failed |
| Recovery/visual | Unproven | No restart/recovery operation or secret-bearing screenshot/trace capture in this harness |

Jupyter does not start kernels, execute notebook code, start/stop a server or edit
existing notebooks. Its fixture user server must already be available at the
exact declared `/user/NAME/` base path. Firefly does not touch existing accounts,
transactions, balances or categories. Only fresh per-run `p0-browser-RUNID`
objects are used. A collision, unexpected object, changed authority, timeout or
API error is not permission for broader cleanup. A failed/ambiguous creation or
cleanup may leave that synthetic object; the worker must reconcile the selected
fixture by its run marker through its normal authorized recovery path. There is
no cache/service/volume cleanup or wildcard deletion here.

Stdout is one secret-free JSON report, including the exact plan/marker/journal/
receipt SHA-256 bindings for the worker to correlate to its operation. Each check
has `target`, `scope`, `state` (`passed`, `failed`, `unproven`) and fixed `code`; earlier failure cannot
be erased by a later successful actor/navigation. Exit **0** means only all
implemented browser-required rows passed. Exit **2** means refusal or any required
failed/unproven row. Every report sets `completeAcceptance: false` and explicitly
marks restart recovery and visual evidence unproven—even on exit 0. This must not
be converted into full product acceptance. Input/runtime failure produces a
fixed generic refusal instead of exception details.

Additional selected apps may be declared with `driver: unimplemented`: browser
SSO/denial/logout still run, but workflow/persistence/cleanup remain unproven and
the command returns 2. Unknown drivers fail validation. To add a real driver,
implement its narrowly scoped browser/protocol round trip in this file and extend
the offline tests; declaring selection alone never accepts missing workflows.

## Isolated source tests

```sh
PYTHONDONTWRITEBYTECODE=1 timeout 120s python3 scripts/test-host-browser-workflows.py
```

Tests use stdlib only, temporary roots inside the checkout, injected test-only
trust anchors, and in-memory browser/protocol mocks. They cover authority CAS,
selected scope, active receipt binding, credential protection, link/path/owner
attacks, shared-context credential-fill counts, native-login rejection, role
denial, logout, API identity/redirect/collision handling, object-specific cleanup,
failed evidence retention and secret-free reporting. They do not import or launch
Playwright, contact apps, access host credentials, mutate host services, or prove
that the deployed versions/selectors/API schemas work. Those remain integration
owner responsibilities on the selected synthetic stack.
