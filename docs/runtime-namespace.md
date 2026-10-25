# P0 v2 pinned data namespace: source-owned Root boundary

`ops/host-admin/provision-p0-v2-namespace.py` is a standalone stdlib Root helper,
not a dispatcher, service controller, mount manager or cleanup tool. Its only
mount target is the **existing new** `/mnt/stack/p0-v2`. No arbitrary paths,
commands, URLs, devices, accounts, capabilities, profiles or teardown switches
are accepted. Root code never imports core/service/user Python or the credential
helper. The credential helper independently verifies the marker contract below.

## Preserve the shared mount

Actual custody is intentionally not flattened into a blanket ancestor exception:

| Path | Required identity |
|---|---|
| `/`, `/mnt` and other privileged ancestors | Root-owned, directories, no symlinks or group/other writes |
| `/mnt/stack` | **Existing UID1000:GID1000, mode2775**, exact mountpoint |
| `/mnt/stack/p0-v2` | **Existing Root0:GID0, mode0711**, exact approved filesystem/device/inode |
| `/mnt/stack/p0-v2/rootless` and `engine` | Existing resolved `p0-runtime` UID/GID, mode0700 |
| `/mnt/stack/p0-v2/rootful` and `engine` | Root0:GID0, mode0700 |

The operator-group-writable `/mnt/stack`, its inherited default ACLs, and all old
lanes/data are preserved. They are never chmodded, chowned, ACL-repaired, replaced
or initialized. A strict child mode alone cannot prevent an ancestor writer from
renaming/replacing that child. The helper therefore pins the reviewed directory
inode using a **self bind mount**, then makes precisely that new mount private.
A non-Root ancestor writer cannot rename/replace a kernel mountpoint. Root and
the host kernel remain trusted; this does not protect against Root unmounting it.

This is a maintenance operation, not a live adoption. Parent must deal explicitly
with the new prototype service/container and exact failed builder objects before
invocation. The helper never stops, removes, adopts, restarts or prunes anything.
It refuses descendant mounts, including active image overlays, and every private
engine container record, including stopped/external build objects.

## Parent-owned private source staging

Review and pin the committed source SHA-256. Stage those exact bytes as a
single-link Root-owned **0400** regular file in a new Root-owned **0700** private
executable directory under `/var/lib`, with strict Root-owned safe ancestors.
Independently verify the staged hash **before execution**. Use
`/usr/bin/python3 -I`; direct non-isolated execution refuses before importing
filesystem-resolved modules. The self-hash check is defense in depth, not a
substitute for the parent's pre-execution gate. Never run from a user checkout,
`/run`, service Python, a container or an imported privileged parent module.

```text
/usr/bin/python3 -I <private-staged-namespace-helper> <mode> \
  --helper-sha256 <64-lowercase-hex-reviewed-source-sha256> \
  --evidence <absolute-user-owned-secret-free-json> \
  --evidence-sha256 <64-lowercase-hex-exact-file-sha256> \
  --evidence-uid <approved-non-system-owner-uid>
```

Evidence is single-link regular JSON, at most256 KiB, owned by the explicitly
approved UID>=1000, without symlinks or group/other writes. Ancestors may belong
to Root or that UID but must not be group/other writable. No evidence path under
the writable shared ancestor is allowed. The exact-sha approval is material Root
intent; inventory output or a locally discovered file is not automatically an
approval. Unit source hashes come from reviewed secret-free immutable inputs.

Closed evidence schema (illustrative numeric identities only):

```json
{
  "version": 1,
  "namespace": {"device": 2049, "inode": 123456, "filesystemId": 987654321},
  "units": {
    "rootless": [
      {"name": "p0-prototype.service", "sourceSha256": "<64-lowercase-hex>"}
    ],
    "rootful": []
  }
}
```

* No extra keys, duplicate JSON keys, nonfinite constants or boolean versions/IDs.
* `namespace` fields are positive integers. Device/inode must match the anchored
  directory; `filesystemId` is `os.fstatvfs(fd).f_fsid`, a stable filesystem
  identity check in addition to the inode. Unsupported/zero IDs refuse.
* Both fixed actors must be explicit. Each list has at most64 unique unit names,
  matching `p0-[a-z][a-z0-9]*(?:-[a-z0-9]+)*.service`, at most96 characters.
  An empty list explicitly approves no installed units for that actor; it is not
  permission to ignore units discovered by native inventory.
* Every declared unit requires its exact source SHA-256. Source paths are derived,
  never supplied: rootless
  `/var/lib/p0-runtime/.config/containers/systemd/<unit-stem>.container`, rootful
  `/etc/containers/systemd/<unit-stem>.container`. Missing or alien source refuses.
* Account identity, primary/supplemental group restrictions, home/shell,
  storage.conf and fixed graphroot/runroot/network paths are the same as in
  [machine-credential-supply.md](machine-credential-supply.md). Rootless identity
  drop uses fixed native `setpriv`, cleared supplemental/inheritable/ambient
  privileges and a clean environment. No user Python is executed as Root.

## Modes and lifecycle ordering

| Mode | Contract |
|---|---|
| `apply` | First reviewed pin, or verify an already complete same-boot marker without repair. Existing foreign/stacked mount refuses. Partial/stale markers require explicit continuation. |
| `resume` | Continue an exact same-boot claimed operation. Reconcile only the expected inode/filesystem and same observed mount metadata; do not mount over an alien or descendant mount. |
| `recheck` | Explicit boot/mount-namespace transition. Require the same approved stable directory/filesystem identity, stopped gates and **no existing target mount**, then repin and publish truthful current observations. Never adopt a new boot's mount using the old ID as authority. |
| `status`, `check` | Read-only verification of current marker, kernel pin, host boot/mount namespace and fixed child custody. Missing/stale/unpinned state refuses; no initialization, mount, ACL operation, repair or native execution. |

Required order:

1. Parent reviews the namespace identity and source-owned unit inventory. Preserve
   synthetic data and immutable failed evidence. Close new owned runtime
   timer/socket/path/boot/rotation triggers and prevent activation races during the
   maintenance interval. Do not operate on old/shared services or global policy.
2. Parent stops only the new owned prototype services using their supported
   lifecycle. Resolve the exact failed builder/container/overlay objects through
   their owning lifecycle. This helper has no cleanup or stop API.
3. Parent preprovisions the account, rootless home/storage configuration and engine
   and needed volatile rootless runroot. Existing rootful engines also require
   their fixed Root-owned runroot/network directories before native inspection;
   after reboot Parent must preprovision missing volatile run directories. Missing
   configuration is not evidence of a clean store. The helper refuses rather than
   run Podman against defaults or repair old directories.
4. Run the privately staged namespace helper with reviewed exact-sha evidence.
   It anchors the namespace with no-follow directory FDs, verifies mountinfo,
   units, native stores and reserves, durably claims the operation and pins it.
5. Only after the kernel pin/private propagation is verified, create any missing
   fixed Rootful directories: namespace `rootful/engine`,
   `/run/p0-v2-rootful/engine`, `/var/lib/p0-v2-rootful/networks` and their dedicated
   parent directories. Newly created inodes alone have UID/GID0, mode0700 and
   inherited default ACL removal set through no-follow FDs. Existing directories
   are checked, never normalized. No rootless or shared parent is repaired.
6. Publish the complete marker. Then supply new ordinary credentials via the
   credential helper. It requires this current verified pin before **any** native
   operation or ancestor exception. It never mounts/provisions on its own.
7. User application activation is Parent's explicit later step. No automatic
   start, rollback, predecessor restart or boot scheduler is installed here.

All mutation gates must settle before the first mount/marker claim/child write.
Native unit checks are observations, not a systemd activation lock: Parent must
hold its maintenance interlock through the entire operation. Namespace/credential
verification conservatively refuses any descendant mount. Consequently later
credential additions/rechecks may require Parent's maintenance window; a running
app is not silently stopped and the pin is never undone to satisfy verification.

Reserves are available RAM16 GiB, root free50 GiB, `/mnt/stack` free100 GiB and
actual `/var/lib` free1 GiB. Floors are checked before mutation and rechecked
before claiming, changing propagation and each fresh child directory. Failure
leaves the narrowly scoped pending state for explicit review, never global repair.

## Fixed native and kernel observations

Root and rootless systemd inventories must not contain unreviewed `p0-*.service`
units. Timer/socket/path inventories must be empty. Each reviewed unit must be
loaded, inactive/failed, MainPID0, empty ControlGroup, empty Job, empty TriggeredBy
and have the exact fixed SourcePath/hash. No cgroup traversal, global process
fallback or process-control command is used.

The only native APIs are:

```text
/usr/bin/systemctl [--user] list-units --all --plain --no-legend p0-*.service
/usr/bin/systemctl [--user] list-unit-files --no-legend p0-*.service
/usr/bin/systemctl [--user] list-units --all --plain --no-legend p0-*.timer p0-*.socket p0-*.path
/usr/bin/systemctl [--user] list-unit-files --no-legend p0-*.timer p0-*.socket p0-*.path
/usr/bin/systemctl [--user] show <reviewed-p0-unit> --no-pager \
  --property=LoadState,ActiveState,MainPID,ControlGroup,Job,SourcePath,TriggeredBy
/usr/bin/podman <fixed-dedicated-store-flags> info --format json
/usr/bin/podman <fixed-dedicated-store-flags> ps --all --external --format json
/usr/bin/mount --no-canonicalize --bind /proc/self/fd/<anchored-fd> /proc/self/fd/<anchored-fd>
/usr/bin/mount --no-canonicalize --make-private /proc/self/fd/<reopened-mounted-fd>
```

Before the pin, Podman graphroot observations are anchored at inherited fixed
`/proc/self/fd/<namespace-fd>/<rootless|rootful>/engine`, not the replaceable shared
pathname. Runroots, storage driver (`overlay`) and Rootful network config always
remain explicit dedicated paths. `info` must return exactly that anchored graph
path, expected runroot and driver. Any running, stopped or external/private
builder container record refuses. A proven missing Rootful engine can be created
only after pinning; a missing rootless engine refuses. There is no default store,
container mutation, pull or network request.

**Native compatibility is not asserted by fixtures.** Parent must qualify its
Podman version's handling of inherited FD graphroot aliases and persisted store
configuration. If it canonicalizes/rejects the alias or would require a different
store, the helper fails closed. Do not replace this pre-pin observation with an
unsafe shared-ancestor pathname to force success. Even observational native tools
may initialize internal metadata in an already configured dedicated store; Parent
owns native qualification, not an assertion that `info` is globally side-effect
free. Source tests run none of these commands.

The make-private step deliberately **reopens** the new mount. The pre-bind FD
still references the covering filesystem mount and must not be used to change
propagation (doing so could affect the shared mount). Native binaries themselves
must be trusted Root-owned single-link files with safe ancestors. Native stdout
is bounded to256 KiB, stderr discarded, deadline30 seconds plus at most5 seconds
cleanup of the exact child. No exceptions/raw output/locals are reported.

Kernel observations are bounded `/proc/self/mountinfo` (4 MiB), boot_id and
mount-namespace identities. The process must share PID1's host mount namespace.
The `/mnt/stack` mount must be exact. The new target must match its parent's
filesystem, derived filesystem-root path, device and source and have a single
read/write private mount with no descendant mounts. Stacked, alien, shared,
slave/unbindable, renamed, missing or stale state refuses.

## Active marker contract v1

Root-private authority: `/var/lib/p0-v2-namespace`, mode0700. Only `active.json`
may exist, Root-owned single-link0400, strict JSON, <=256 KiB. Nonblocking directory
flock is exclusive for mutations, shared for read-only checks. This is **active
namespace custody**, not an experiment backup, snapshot, archive or recovery copy.

```text
{
  version: 1,
  state: claimed | pinned,
  owner: <independent-opaque-128-bit-hex>,
  evidenceSha256: <exact-approved-public-evidence-sha256>,
  namespace: { device: <st_dev>, inode: <st_ino>, filesystemId: <f_fsid> },
  bootId: <current-kernel-boot-UUID>,
  mountNamespace: { device: <nsfs-device>, inode: <host-mnt-namespace-inode> },
  mount: null | {
    id: <mount-id>, parent: <parent-mount-id>, device: <major:minor>,
    root: <derived-filesystem-root>, target: /mnt/stack/p0-v2,
    options: <kernel-list>, optional: <kernel-propagation-list>,
    fsType: <kernel-filesystem-type>, source: <kernel-source>
  },
  integrity: <private-full-record-corruption-check>
}
```

Every publication compares the exact previous bytes and device/inode/mode/UID/GID/
link-count/size/mtime/ctime, fsyncs a new private0400 inode, atomically renames it
inside the locked authority and fsyncs the directory. Unknown/interrupted
`.publish-*` entries fail closed and remain; there is no cleanup API. The internal
checksum is not a defense against an attacker already holding Root.

The `claimed` record is durable **before** self-bind; mount observations are saved
before and after make-private. `pinned` is published only after child checks/
provisioning. A crash after bind can explicitly resume the matching observed
mount without a second bind. A crash after make-private can reconcile removal of
propagation tags on the **same** exact mount ID/metadata; changed IDs, added tags
or alien sources refuse. Missing/partial child configuration may require a
separately reviewed Parent disposition, not blanket permission repair.

After boot or host mount-namespace change, status and credential supply refuse
the stale marker. Explicit `recheck` keeps the approved filesystem/directory
identity and opaque owner, redoes stopped gates, requires target mount absence,
and records the **new** boot/mount-namespace/mount observations. Only that explicit
transition may refresh the approved public unit-inventory evidence digest (for
later installed apps); it reruns all actual unit/source/container gates against
the new reviewed inventory. Same-boot apply/resume/status/check cannot change the
evidence binding. No namespace identity or credential value is adopted by this
refresh. No assertion is made that device numbering, mount IDs or mount-namespace
IDs survive reboot.
If even the stable identity/device evidence changes, fail closed for a new Parent
review; do not synthesize matching IDs or adopt a mount from an old marker.

Public reports contain only version/scope/mode/state, namespace identity, current
bootId/mountId, opaque owner and `installationCertified:false`; refusals expose
fixed reason codes. There are no credential values, hashes of credential values,
unit source, raw native diagnostics or service exceptions in these reports.

## Source-only evidence

```text
python3 -I -m unittest discover -s tests_v2 -p test_runtime_namespace.py -v
python3 -I -m unittest discover -s tests_v2 -p test_machine_credentials.py -v
```

Fake runners and private temporary fixtures exercise pin/claim/reopen/private
ordering, crash reconciliation, boot recheck, marker CAS/locking, exact units and
stores, active/PID/cgroup/job/trigger/container/submount rejection, fresh-inode-only
ACL normalization and independent matching marker verification by both helpers.
Invalid boundary cases are exercised through the credential supply flow and fail
before native secret effects; a valid pinned fixture succeeds. No test invokes
Root, mount, Podman, systemd, services, real credentials or remote APIs. Actual
Root/native review, mounting, compatibility and installed acceptance remain
Parent-owned and are **not certified** here.
