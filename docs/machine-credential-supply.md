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
4. Invoke `/usr/bin/python3 -I <staged-file>` with the exact arguments below.
   Non-isolated direct CLI execution refuses before filesystem-resolved imports.
   Do not import the helper into a privileged parent Python interpreter.
5. Supply the explicitly approved, ordinary-service intent file and its exact
   byte SHA-256 and owner UID. The file must be absolute, bounded to 256 KiB,
   single-link, regular, not a symlink and not group/other writable. Its UID must
   be the explicitly supplied non-system UID (>=1000). Every ancestor must be a
   directory owned by Root or that UID, without symlinks or group/other writes.
   A home directory is acceptable; `/tmp` is not. Do not include credentials.
6. Provision the runtime account, dedicated engine stores, run directories and
   rootful network directory beforehand. This helper never provisions them.

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
    {"name": "app-bootstrap", "actors": ["rootless"]}
  ]
}
```

* No additional fields at any level; duplicate JSON keys and nonfinite constants
  refuse. Version is integer 1, not a boolean. Classification is exactly
  `ordinary-service`.
* `resources` has 1–64 entries with unique names. A name is at most 48 characters,
  matching `[a-z][a-z0-9]*(?:-[a-z0-9]+)*`. It is a resource identifier, not a path.
* `actors` has 1–2 unique entries, only `rootless` and/or `rootful`.
* Names containing `vault`, `keykeeper`, `bao` or `owner` refuse. `postgres-admin`
  is explicitly protected: **preexisting `p0-postgres-admin` is never inspected or
  touched**. The caller must deliberately exclude it. This is a reserved-name
  defense in addition to, not a substitute for, reviewed ordinary-service intent.
* Native names are exactly `p0-<name>`. Do not put the native prefix in an intent
  unless the extra prefix is actually intended.
* Binding is to the exact intent bytes. Reordering, whitespace, actor-set changes,
  added resources or version changes require a different intent, which the active
  record refuses. This bounded helper supports one fixed active intent, not
  incremental adoption or a general multi-tenant credential registry.

## Fixed actors and native interface

Only `p0-runtime` and Root are used. `pwd` must resolve `p0-runtime` to UID/GID
>=1000, home `/var/lib/p0-runtime`, shell `/usr/sbin/nologin`, and an empty-member
primary group named `p0-runtime`. Supplemental group membership refuses.

| Actor | Graphroot | Runroot | Network config |
|---|---|---|---|
| rootless | `/mnt/stack/p0-v2/rootless/engine` | `/run/user/<resolved-uid>/containers` | Existing user native configuration; no new profile |
| rootful | `/mnt/stack/p0-v2/rootful/engine` | `/run/p0-v2-rootful/engine` | `/var/lib/p0-v2-rootful/networks` |

All required directories must already exist and have owned, non-writable,
non-symlink ancestors. Rootless leaf directories must belong to the resolved
account. Rootful directories and ancestors must belong to Root. Rootless
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
for the exact child. No global process observation or termination is used.

## Active Root custody and explicit recovery

The only production custody root is `/var/lib/p0-v2-machine-credentials`, **0700**,
Root-owned, with safe Root-owned ancestors. `apply` may exclusively create this
new directory; it never normalizes an existing directory. The directory itself
is locked using nonblocking `flock` (exclusive for mutating modes; shared for
inspection). Only `active.json` may already exist. Unknown entries, including an
interrupted `.publish-*`, cause refusal and are preserved for explicit parent
review; there is no automatic cleanup or retry.

`active.json` is single-link, Root-owned **0400** strict JSON:

```text
{
  version: 1,
  intentSha256: <exact-intent-digest>,
  owner: <opaque-random-128-bit-hex>,
  resources: {
    <resource>: {
      version: <opaque-random-128-bit-hex>,
      value: <64-character-base64-of-48-locally-random-bytes>,
      actors: { <actor>: { state: prepared|claimed|uncertain|complete, id: null|<native-id> } }
    }
  },
  integrity: <internal-record-corruption-check>
}
```

This is **active authoritative credential custody**, not an experiment backup,
archive or snapshot. A value is generated exactly once per new resource using
`secrets.token_bytes(48)`, encoded into 64 ASCII bytes, and the **same bytes** are
piped to each listed actor. Values never appear in reports, argv, environment,
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
fake native runners/processes. They prove equal generated bytes across actors
without displaying them, durable claims before effects, crash/metadata resume,
foreign-name rejection, changed IDs, uncertainty/no replay, schema/hash/integrity
refusals, CAS/lock/link/mode/ancestor custody, fixed identity/store flags, output
bounds/deadlines, sanitized errors, resource gates and read-only status/dry-run.
No fixture is installed proof. **Actual native compatibility, private Root staging
and installed service acceptance remain parent-owned and are not certified here.**
