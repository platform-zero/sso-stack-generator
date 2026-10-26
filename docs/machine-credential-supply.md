# P0 v2 ordinary machine-credential supply

`ops/host-admin/provision-p0-machine-credentials.py` is a standalone, stdlib-only
Root helper. It creates **new ordinary service credentials only** in the new P0
namespaces. It is not Keykeeper, OpenBao, vault migration, owner credential access,
rotation, recovery export, or a general privileged command runner. It never reads
backend credential values, adopts existing credentials, removes secrets, or repairs
old permissions. There is no application-specific password table.

## Parent-owned staging and invocation contract

The parent lifecycle owns deployment and must:

1. Review and pin the helper's source SHA-256 from its committed source.
2. Stage precisely those bytes as a single-link, Root-owned **0400** regular file
   beneath a new Root-owned **0700** private directory under `/var/lib`. Every
   ancestor must be Root-owned, non-symlink and not group/other writable. This is
   executable-source staging, not `/run`, a user checkout, a service image, or an
   import of user/core/service Python. Use a filesystem permitting execution.
3. Independently hash-verify the staged inode **before execution**. The helper's
   subsequent self-check is defense in depth, not a bootstrap trust mechanism.
4. Invoke trusted `/usr/bin/python3 -I <staged-file>` from a clean privileged
   launcher environment (no caller library/preload injection), with the arguments below.
   Non-isolated direct CLI execution refuses before filesystem-resolved imports.
   Do not import the helper into a privileged parent Python interpreter.
5. Supply the explicitly approved, ordinary-service intent file and its exact
   byte SHA-256 and owner UID. The file must be absolute, bounded to 256 KiB,
   single-link, regular, not a symlink and not group/other writable. Its UID must
   be the explicitly supplied non-system UID (>=1000). Every ancestor must be a
   directory owned by Root or that UID, without symlinks or group/other writes.
   A home directory is acceptable; `/tmp` is not. Do not include credentials.
6. Provision the runtime account, then use the separately reviewed namespace
   helper and its current-boot pinned marker as described in
   [runtime-namespace.md](runtime-namespace.md). Provision dedicated engine stores,
   run directories and network configuration before supply. This credential
   helper never mounts or provisions actor directories.

CLI (documentation only; no deployment is performed by the source tests):

```text
/usr/bin/python3 -I <private-staged-file> <mode> \
  --helper-sha256 <64-lowercase-hex-source-sha256> \
  --intent <absolute-user-owned-json-file> \
  --intent-sha256 <64-lowercase-hex-exact-file-sha256> \
  --intent-uid <approved-non-system-uid>
```

All four options are required in every mode. The SHA-256 inputs identify source
and public intent, **not credential values**. No environment-driven switches,
custom runners, custom stores, arbitrary URLs, command strings or credential
arguments are accepted. Exit status is 0 on a report, 2 on refusal. Parser errors,
OS/JSON/native failures and exceptions produce bounded public JSON, never
exception strings or native diagnostics. Core dumps are disabled in execution.

Modes:

| Mode | Meaning |
|---|---|
| `apply` | Prepare a fresh active record and create new targets. An existing fully complete record is metadata-verified, not rotated. An existing partial record requires `resume`. |
| `resume` | Explicitly reconcile the exact existing record and matching native metadata; create only actors still `prepared`. No record means refusal, not generation. |
| `status` | **Offline custody status**, not an installed/native/backend health assertion. No native calls, directory creation, record updates or initialization. |
| `dry-run` | The same offline inspection, with a different report mode. Does not claim that stores, reserves or native names have passed deployment preflight. |

## Intent v1: exact closed schema

```json
{
  "version": 1,
  "classification": "ordinary-service",
  "resources": [
    {"name": "boot-shared", "actors": ["rootless", "rootful"]},
    {"name": "app-bootstrap", "actors": ["rootless"],
     "policy": {"encoding": "base64url", "entropyBytes": 32}}
  ]
}
```

* No additional fields at any level; duplicate JSON keys and nonfinite constants
  refuse. Version is integer 1, not a boolean. Classification is exactly
  `ordinary-service`.
* `resources` has 1–64 entries with unique names. A name is at most 48 characters,
  matching `[a-z][a-z0-9]*(?:-[a-z0-9]+)*`. It is a resource identifier, not a path.
* `actors` has 1–2 unique entries, only `rootless` and/or `rootful`.
* `policy` is optional. Its closed shape is
  `{"encoding":"base64url","entropyBytes":32}` with encoding exactly one of
  `base64url`, `base64url-unpadded`, `hex`, and entropyBytes exactly32 or48.
  Omission **still** normalizes to padded `base64url` with48 entropy bytes.
  Standard `+/` base64, unknown encodings, weak/other entropy sizes, boolean sizes
  and extra fields refuse. This is a generic closed policy, not an application
  map, expression evaluator or generator API.
  * `base64url`:32 bytes =>44 characters with exactly one `=`;48 =>64 characters
    with no padding. Existing OAuth-cookie/default behavior is unchanged.
  * `base64url-unpadded`:32 bytes =>**43** characters;48 =>64. No `=` is accepted.
  * `hex`:32 bytes =>64 lowercase hex characters;48 =>96. No prefix, uppercase,
    whitespace or terminator is accepted.
  All encodings round-trip to exactly the selected entropy count. Base64 pad bits
  must be canonical, not merely decodable. Formats are policy-bound even where
  padded/unpadded48-byte encodings happen to have identical bytes.
  Consumer-owned declarations choose the format explicitly. For example, the
  reviewed proposed catalog04 contract requires four independent32-byte hex
  materials and one independent32-byte unpadded URL-safe material for Forgejo.
  The latter must be43 characters, not hex64/padded44/default64: the consumer's
  native decoder can otherwise silently regenerate plaintext INI. The helper
  contains **no Forgejo resource inventory** and never guesses this format;
  Parent must materialize the exact reviewed generic policies. Actual native
  unchanged-INI checks and consumer acceptance remain Parent/consumer-owned.
* Names containing `vault`, `keykeeper`, `bao` or `owner` refuse. `postgres-admin`
  is explicitly protected: **preexisting `p0-postgres-admin` is never inspected or
  touched**. The caller must deliberately exclude it. This is a reserved-name
  defense in addition to, not a substitute for, reviewed ordinary-service intent.
* Native names are exactly `p0-<name>`. Do not put the native prefix in an intent
  unless the extra prefix is actually intended.
* Binding is to the exact intent bytes. Reordering, whitespace, actor-set or policy
  changes produce a different intent identity. Each digest has independent
  custody, but a new intent must contain **NEW resource names only**, across all
  actors. Earlier resources remain in their original intent and applications
  reuse those native references without resupplying or adopting them here.
  Changed policy for an already claimed name refuses; no value/version rotates.
  The authority is bounded to 64 intent directories and 512 aggregate resources
  (including prepared or uncertain claims), with 64 resources per intent.

## Fixed actors and native interface

Only `p0-runtime` and Root are used. `pwd` must resolve `p0-runtime` to UID/GID
>=1000, home `/var/lib/p0-runtime`, shell `/usr/sbin/nologin`, and an empty-member
primary group named `p0-runtime`. Supplemental group membership refuses.

| Actor | Graphroot | Runroot | Network config |
|---|---|---|---|
| rootless | `/mnt/stack/p0-v2/rootless/engine` | `/run/user/<resolved-uid>/containers` | Existing user native configuration; no new profile |
| rootful | `/mnt/stack/p0-v2/rootful/engine` | `/run/p0-v2-rootful/engine` | `/var/lib/p0-v2-rootful/networks` |

All required directories must already exist and have owned, non-writable,
non-symlink ancestors, with exactly one independently verified exception:
`/mnt/stack` is preserved as UID1000:GID1000 mode2775. It is accepted only for
paths at/below the exact Root0:0 mode0711 **kernel-pinned** `/mnt/stack/p0-v2`
boundary, with a strict Root-private namespace marker matching current boot,
host mount namespace, filesystem ID, device/inode and actual private mount metadata.
The namespace marker is **v2**, with an exact `cloneMountId` durably preclaimed
before FD attachment and equal to the current kernel mount ID. Legacy namespace
v1 markers cannot prove that ownership and are not auto-migrated. This is separate
from credential record v2 and intent/evidence/report v1.
No caller path outside that boundary gets an ancestor exemption. Missing,
claimed, corrupt, stale, renamed, foreign, shared, stacked or unpinned mounts and
any descendant mount refuse **before any native call**, including `info`.
The marker verifier is standalone code in this helper; Root does not import the
namespace helper or service/core/user modules. Namespace marker details and
maintenance ordering are in [runtime-namespace.md](runtime-namespace.md).
Rootless home/namespace-child/engine/runroot directories must have the resolved
UID/GID and mode0700. Rootful child/engine/runroot/network directories must be
Root-owned, GID0 and mode0700. Other ancestors retain the strict ownership rule. Rootless
`~/.config/containers/storage.conf` must be a single-link **0600** account-owned
file with exactly the storage text emitted by `provision-p0-runtime.py`:

```toml
[storage]
driver = "overlay"
runroot = "/run/user/<resolved-uid>/containers"
graphroot = "/mnt/stack/p0-v2/rootless/engine"
```

`/usr/bin/podman` and `/usr/bin/setpriv` must be single-link, Root-owned,
non-symlink, non-writable native binaries with safe ancestors. Rootless execution
uses fixed `setpriv --reuid <uid> --regid <gid> --clear-groups --inh-caps=-all
--ambient-caps=-all /usr/bin/podman ...` and a newly constructed environment
containing only PATH, LC_ALL, HOME and XDG_RUNTIME_DIR. Ordinary preprovisioned
rootless subordinate-ID helpers remain usable; the helper adds no profiles,
capabilities, accounts or host policy. Rootful Podman always has explicit
`--root`, `--runroot`, `--storage-driver overlay`, `--network-config-dir` flags,
never the shared/default Root store. Rootless graphroot/runroot/driver flags are
also explicit.

Before **any secret operation**, filesystem/config checks run and native
`info --format json` must report the exact expected `store.graphRoot`,
`store.runRoot` and `store.graphDriverName`. In the CLI, these checks happen before
creation of the custody directory, and are rechecked within the supply flow.
Preflight captures the verified namespace marker bytes/file identity and current
pin, plus actor directory device/inode/UID/GID/mode and exact rootless config
bytes/file identity. Before **and after every native call**, including `info`,
`exists`, `inspect` and `create`, those authorities are revalidated. A changed
marker/mount/layout refuses, even after native exit0; uncertain effects retain
claims rather than being replayed. Layout checks do not compare engine-directory
mtime, which legitimate backend metadata operations may change.

Every native graphroot is the literal canonical path in the table, never an
inherited-FD alias or persisted FD-number identity. This is not a fallback from
an alias failure: Host Root may use these paths only under the complete verified
kernel pin. This credential helper has **no** unpinned/native observation mode.
The namespace helper's separately bounded pre-pin observation is unprivileged
Rootless-only and requires fresh absent/empty Rootful state; it grants no secret
supply authority. Initialized unpinned Rootful stores and normal populated
Rootful reboot/repin remain unsupported, not automatically repaired. Namespace
preclaims without attachment likewise require reviewed disposition. Details and
remaining native/lifecycle gates are in [runtime-namespace.md](runtime-namespace.md).
The parent's namespaces must already be provisioned: even native `info` can
initialize internal metadata within a dedicated store, so mutating modes are not
advertised as side-effect-free preflight. Status/dry-run never call `info`.

The only secret commands are exact-name `secret exists`, metadata-only `secret
inspect`, and `secret create --driver file --label ... p0-<name> -`. Absence is
accepted only from `secret exists` status 1; other failures are uncertain, not
absence. Inspect must report one exact name, a bounded alphanumeric ID, driver
`file` without driver options and the exact expected ownership labels. Native
stdout is bounded to 256 KiB and parsed only as metadata; stderr is discarded.
Native calls have 30-second deadlines; cleanup may wait at most another 5 seconds
for the exact newly created session/process group. Unsettled output/deadline
failure sends SIGKILL to that group before reaping its leader; settled commands
are not signalled. No global process observation or termination is used. Cleanup
timeout remains indeterminate, not proof of no kernel-waiting descendant; Parent
must reconcile its exact supervisor scope before another affected operation.

## Active Root custody and explicit recovery

The production authority is `/var/lib/p0-v2-machine-credentials`, **0700**,
Root-owned, with safe Root-owned ancestors. Each intent has independent custody:

```text
/var/lib/p0-v2-machine-credentials/intents/<exact-intent-sha256>/active.json
```

`intents` and each digest directory are also Root0700. `apply` may exclusively
create these new directories; it never normalizes old directories. The authority
and selected intent directory are locked using nonblocking `flock` (exclusive for
mutating modes; shared for inspection). The global authority lock serializes
cross-intent name claims: all prior records are strictly validated and scanned
before generation or native effects, and a name collision refuses even when a
prior actor is merely prepared and no native secret exists yet. Native foreign
names still refuse independently. No old intent/value is updated when adding a
new one. Existing resources are reused externally by their original references.

Only `intents` may exist at the authority root; only bounded lowercase digest
directories beneath it; only `active.json` inside a digest directory. Unknown
entries or interrupted `.publish-*` files cause refusal and are preserved.
A legacy root `active.json` or record version1 is **never auto-migrated**. Empty
new intent directories can remain after a refused create; there is no cleanup,
rotation, legacy-label repair or force/replay API.

`active.json` is single-link, Root-owned **0400** strict JSON:

```text
{
  version: 2,
  intentSha256: <exact-intent-digest>,
  owner: <opaque-random-128-bit-hex>,
  resources: {
    <resource>: {
      version: <opaque-random-128-bit-hex>,
      policy: { encoding: base64url|base64url-unpadded|hex, entropyBytes: 32|48 },
      value: <canonical-selected-encoding-of-exactly-policy-entropy-bytes>,
      actors: { <actor>: { state: prepared|claimed|uncertain|complete, id: null|<native-id> } }
    }
  },
  integrity: <internal-record-corruption-check>
}
```

This is **active authoritative credential custody**, not an experiment backup,
archive or snapshot. A value is generated exactly once per new resource using
`secrets.token_bytes(policy.entropyBytes)` and the selected canonical encoding
(43/44/64/96 ASCII bytes); the **same encoded bytes** are piped to every listed actor. Each
resource draws independent entropy; distinct resources never share one generated
value, even if their policies match. The
normalized policy is bound to the exact intent, record and its opaque resource
version. Load validates the policy against the intent, exact decoded length,
lowercase hex or URL-safe alphabet and exact selected padding by an encode/decode
round trip. Unpadded policies never accept padded values or silently strip them;
hex policies never normalize uppercase/prefixes/whitespace. A policy
change never silently replaces or rotates any existing resource. Values never appear in reports, argv, environment,
world-readable temporary files or native diagnostics. Native output is never
forwarded. Ownership/version IDs are independently random, not credential-value
fingerprints. The internal full-record integrity check never leaves Root custody;
it detects corruption but does not pretend to defend against an attacker already
holding Root and able to rewrite the entire trusted record.

The helper checks exact version/schema/intent binding, actor sets, ID formats,
encoding and integrity when loading. Before every write it reads back and compares
the exact previous bytes **and** device/inode/mode/UID/GID/link-count/size/mtime/
ctime identity. A new private **0400** inode is fsynced and atomically renamed
within the locked Root directory, then that directory is fsynced. Only newly
created temporary inodes have their modes set; no old credential or directory is
chmodded. A failed publication is retained, not silently repaired.

Fresh supply checks every target for absence before publishing a prepared record.
An existing name without the exact record is foreign, even if it looks like a P0
secret. Creation races do not enable replacement. All actor metadata is checked
before any subsequent create. An empty newly created custody directory can remain
after a foreign-name refusal; no credential record/value is generated in that case.

Native labels must exactly equal:

```text
p0.machine.owner   = record.owner
p0.machine.version = resource.version
p0.machine.intent  = record.intentSha256
p0.machine.class   = ordinary-service
```

State transitions:

1. Persist `prepared` value/version and actor claims before effects.
2. Recheck resource floors and durably persist `claimed` immediately before create.
3. Create with a small stdin pipe, then inspect exact metadata. Persist `complete`
   and native ID only after a matching observation.
4. An uncertain exception persists `uncertain` and returns a fixed reason. A hard
   crash can leave `claimed`. Neither permits blind create replay.
5. Explicit `resume` reconciles a `claimed`/`uncertain` actor **only if** its native
   name has exactly matching labels (and matching ID if already recorded). It can
   then create remaining `prepared` actors with the original bytes. Changed IDs,
   foreign labels, a native name for an unclaimed actor, or absence after a claim
   all refuse without further create. A previously complete but now absent actor
   also refuses. There is no automatic rollback or credential deletion.

Thus a crash **before** an external effect but **after** its durable claim may
require a separately reviewed parent disposition; uncertainty is not converted
into evidence of absence or authority to replay. No reset/force/replay switch is
provided. The helper never prints stored values for manual recovery.

Mutating CLI invocations require available RAM >=16 GiB, root free >=50 GiB,
`/mnt/stack` free >=100 GiB, and actual `/var/lib` staging free >=1 GiB. These
floors are checked before even creating custody and immediately before every
credential create. Unknown custody, mismatched actors/stores or insufficient
reserves refuse; they do not initialize defaults or alter host policy.

## Public report

Success reports contain `version: 1`, `scope: ordinary-service`, `mode`,
`installationCertified: false`, opaque `owner` (null if absent) and a `resources`
list of `{name, version, actors: {actor: {state, id}}}`. Missing custody reports
null versions/IDs and `absent` state. No `value`, `integrity`, backend diagnostics,
credential hash or credential fingerprint is reported. Refusals contain only
`version`, `scope`, `refused: true`, a fixed `reason` and
`installationCertified: false`.

## Source-only qualification

```text
python3 -I -m unittest discover -s tests_v2 -p test_machine_credentials.py -v
```

Tests import only this standalone source into an unprivileged test interpreter.
They use private temporary fixture directories, test-local ownership mapping and
fake native runners/processes. They prove all three exact32/48-byte encoding policies, rejection of
noncanonical hex/unpadded/padded forms, five independent consumer-format entropy
draws, metadata-bound resume without regeneration, and equal generated bytes
across actors without displaying them, independent incremental intents,
cross-intent claim collision/locking, namespace-boundary refusals, durable claims
before effects, crash/metadata resume,
foreign-name rejection, changed IDs, uncertainty/no replay, schema/hash/integrity
refusals, CAS/lock/link/mode/ancestor custody, fixed identity/store flags, output
bounds/deadlines, sanitized errors, resource gates and read-only status/dry-run.
Discriminating fake tests also reject missing preflight, marker/mount/directory
changes before native process creation, and authority changes after an otherwise
successful canonical native command. Native I/O-only tests stub authority checks
explicitly; they do not qualify real filesystem or kernel ownership.
No fixture is installed proof. **Actual native compatibility, private Root staging
and installed service acceptance remain parent-owned and are not certified here.**
