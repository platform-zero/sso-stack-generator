# P0 v2 pinned data namespace: bounded Root authority

> **CRITICAL07 SUPERSESSION:** Native10 proved old-mount-namespace UID1000 can
> rename the Root0 bound dentry under its mutable parent; the Host target follows
> with SAME mount ID. The v2 custody premise below is superseded, NOT native
> acceptance. Current source `pin` (all modes) and engine observers fail closed
> with `protected-view-v3-integration-required`. Actual old records/staged sources
> remain untouched. Task05/06 mechanisms are historical regressions only until
> independent protected-parent v3/native/manager/actual-unshare integration.
> See [native-view-custody.md](native-view-custody.md) for containment, precise
> remaining backend cells and protected-view protocol. No publication/boot claim.

`ops/host-admin/provision-p0-v2-namespace.py` is a standalone stdlib helper, not a
dispatcher, controller, general mount manager or cleanup tool. Its only mount
target is the **existing new** `/mnt/stack/p0-v2`. It accepts no caller commands,
devices, capabilities, profiles, arbitrary mount paths or teardown switches.
Root never imports service/core/user Python or the credential helper. The latter
independently verifies the same namespace-marker contract.

**Task05 is source-only qualification.** Parent has independently qualified an
initial APPLY/CHECK of the predecessor and canonical pre/post observations, with
Rootful metadata initialized but no Rootful images/services. That is not
qualification of this revision's boot recovery, relay or evidence-admission paths.
Do not use these new paths against application stores before Parent's independent
private Root review/staging and exact-source native qualification.

## Threat boundary and preserved custody

| Path | Required custody |
|---|---|
| `/`, `/mnt`, other privileged ancestors | Root-owned directories, no symlinks or group/other writes |
| `/mnt/stack` | Existing UID1000:GID1000, mode2775, exact mountpoint |
| `/mnt/stack/p0-v2` | Existing Root0:GID0, mode0711, approved device/inode/filesystem ID |
| namespace `rootless` and `engine` | Existing resolved `p0-runtime` UID/GID, mode0700 |
| namespace `rootful` and `engine` | Root0:GID0, mode0700 |

The shared parent's inherited default ACLs, modes, owners and existing lanes/data
are preserved. Strict child modes alone do not stop a shared-ancestor writer from
renaming/replacing a child. The helper clones the reviewed directory mount via
held FDs, attaches it to that exact directory FD and verifies the resulting
canonical kernel mountpoint. **The old claim that this prevents a non-Root
ancestor writer moving the mountpoint was falsified by Native10 in an older mount
namespace.** Same ID/private state does not secure that pathname. Only the new
independent protected-parent target/view direction addresses that attack; the
old checks here are mechanism/forensic evidence, not native authority. A pre-attachment rename causes refusal, not privileged native
access through a replacement. No permission repair makes a replaceable pathname
safe for Host Root native storage access.

### Canonical native-store authority, not an alias fallback

Podman always receives the fixed **literal canonical graphroot**:

* rootless: `/mnt/stack/p0-v2/rootless/engine`, overlay,
  `/run/user/<resolved-uid>/containers`;
* rootful: `/mnt/stack/p0-v2/rootful/engine`, overlay,
  `/run/p0-v2-rootful/engine`, network `/var/lib/p0-v2-rootful/networks`.

There are no `/proc/self/fd/.../engine` native aliases, inherited native FDs,
canonicalization retries or default-store fallbacks. FD numbers are not durable
storage identity. Even `info` can initialize metadata; it is not advertised as
side-effect-free.

**Before pinning**, the only native engine observation is Rootless Podman after
fixed identity drop to `p0-runtime`. Root holds no-follow namespace/actor/engine
FDs and checks their ownership, device/inode and configuration before and after
both `info` and `ps`. Canonical `graphRoot`, runroot and overlay must match exactly;
all containers, including stopped/external builder objects, refuse. An ancestor
replacement can cause failure or change what the unprivileged actor observes,
but it does not grant Host Root a pre-pin native storage path. Parent must hold
its maintenance interlock: observations are not an activation lock or proof
against a malicious trusted runtime actor.

**Initial Rootful pre-pin circularity is resolved conservatively**, not by running
Host Root Podman through the shared parent: the reviewed Rootful unit list must be
empty, native unit inventories must agree, and no-follow inspection requires the
Rootful actor/engine to be absent or correctly Root-owned0700 and **empty**. The
exact absence/empty-inode witness must remain unchanged around observations.
Existing metadata, installed Rootful units, symlinks or alien custody refuse
before any native store call or mount/marker effect. First pin must precede
Rootful unit publication/store initialization. The helper never deletes metadata
or moves a store to manufacture freshness. Evidence-v2 relays also count as
Rootful units here; initial apply does not use them as an exception.

### Explicit complete-owned boot recheck (E1)

Only explicit `recheck` may transition a **complete prior pinned v2** claim to a
changed boot or host mount namespace. The private record must have valid schema,
integrity, owner/evidence binding and exact saved private mount/clone-ID metadata.
The stable approved namespace device/inode/`f_fsid` must still match Root0:G0:0711.
There must be no current target, stacked mount or descendants. Changed stable
identity refuses; no persistence across actual reboot is assumed.

Before any current Host Root storage authority exists, `RepinPermit` independently
opens and holds no-follow Root0:G0:0700 `rootful` and `engine` FDs **relative to
that held namespace**, even when populated. It checks their complete directory
custody/identity against relative reopened FDs and the canonical namespace around
the gates and every native observation. The shared-parent writer cannot mutate
these Root-only descendants; a namespace rename/swap fails canonical identity.
Root and the runtime actor remain trusted and Parent holds the activation
interlock. This is prior Root namespace custody, not adoption of arbitrary
foreign paths/data. Marker v2 does **not** store historical engine inode IDs:
we do not invent that history or claim cross-boot inode continuity for the store.
Current independently held store identities must remain unchanged during repin.

The permit exempts only the initial **freshness** restriction; it never authorizes
pre-pin Root Podman. Exact stopped unit/source/trigger/listener gates, canonical
unprivileged Rootless observations and reserves precede the fresh clone. Durable
new clone ID, exact attach and post-attach private/kernel verification precede
current private metadata publication and **all** Rootful canonical info/ps. Any
container record, including stopped/native external objects, still refuses.
Existing data/images/volume files are not scanned, reset, repaired or deleted.
Only absent fixed volatile children may be freshly provisioned after the pin;
existing custody is checked without repair. A missing persistent Rootful engine
or wrong owner/mode/identity is not a fresh boot-recovery store.

Stale claimed, incomplete, legacy or wrong-binding states cannot bootstrap this
permit. Replacing the old complete claim with the new durable claim deliberately
has a conservative crash boundary: if attachment/current private metadata cannot
be proved, review may be needed, not automatic history reconstruction. A durable
detached preclaim without target attachment still refuses replay. Current
same-boot partial recovery remains restricted to its exact preclaimed mount.

**After attachment and verified private propagation**, the current Root-private
claim, preclaimed mount ID, boot/mount namespace, directory/filesystem identity
and actual mount metadata grant bounded Host Root native authority. Rootful
canonical `info`/`ps` are then allowed, with anchored actor/engine and pin checks
around each call. Existing runroot/network custody must be valid. The credential
helper is stricter still: it requires a complete `pinned` marker and rechecks
marker bytes/file identity, actual pin and actor layout before and after every
native call. See [machine-credential-supply.md](machine-credential-supply.md).

## Parent-owned private source staging and intent

Review and pin committed source SHA-256. Stage exactly those bytes as a single-link
Root-owned0400 file in a new Root-owned0700 **executable** private directory under
`/var/lib`, with safe Root ancestors. Independently verify the staged inode/hash
**before execution**. Invoke trusted `/usr/bin/python3 -I` from a clean privileged
launcher environment (including no caller library/preload injection). Do not run
from a user checkout, noexec `/run`, service Python or an imported parent module.
The self-hash check is defense in depth, not bootstrap trust. Non-isolated direct
execution refuses before filesystem-resolved imports.

Documentation-only command shape:

```text
/usr/bin/python3 -I <private-staged-namespace-helper> <mode> \
  --helper-sha256 <reviewed-64-lowercase-hex-source-sha256> \
  --evidence <absolute-approved-user-owned-secret-free-json> \
  --evidence-sha256 <exact-file-64-lowercase-hex-sha256> \
  --evidence-uid <approved-owner-uid-at-least-1000>
```

Evidence is single-link regular JSON, <=256 KiB, exact approved UID, no symlinks
or group/other writes; ancestors must belong to Root/that UID and be non-writable
by others. Do not stage evidence beneath the shared writable ancestor. Hash
approval is material Root intent, not automatic approval of discovered inventory.
Closed evidence schema v1 (illustrative IDs):

```json
{
  "version": 1,
  "namespace": {"device": 2049, "inode": 123456, "filesystemId": 987654321},
  "units": {
    "rootless": [{"name": "p0-prototype.service", "sourceSha256": "<64-lowercase-hex>"}],
    "rootful": []
  }
}
```

No unknown/duplicate keys, nonfinite constants or boolean versions/IDs. Namespace
IDs must be positive integers matching anchored `st_dev`, `st_ino`,
`os.fstatvfs(fd).f_fsid`; unsupported/zero filesystem IDs refuse. Both actor lists
are explicit, each <=256 unique `p0-[a-z][a-z0-9]*(?:-[a-z0-9]+)*.service` names
<=128 characters. Rootless names remain `p0-*` in the dedicated runtime user
manager. **Rootful application names must use reserved `p0-v2-*`**: the host
system manager already owns protected historical `p0-*` services/transient jobs,
which are not this namespace's inventory or authority. Bootstrap/control units
must stay outside the application prefix, so the helper does not include itself
in the stopped application inventory. Unknown units within the reserved scope
still refuse; this is not a foreign-unit exception list.

Empty means no installed scoped units, not permission to ignore them. Each entry
accepts optional closed `kind: container|network|volume`, default `container` for
existing v1 evidence. Source derivation is exact: `p0-x.service` maps to
`p0-x.container`; explicit network `p0-network-x-network.service` maps to
`p0-network-x.network`; explicit volume `p0-x-volume.service` maps to `p0-x.volume`.
The same suffix rules apply to reserved Rootful `p0-v2-*` names. A mismatched kind
or suffix refuses. Fixed source bases are
`/var/lib/p0-runtime/.config/containers/systemd` or `/etc/containers/systemd`,
with the exact reviewed hash. No caller SourcePath or source execution is allowed.
Source-parent generic, exact and dash-prefix Quadlet drop-ins refuse; inaccessible
metadata is not treated as absence. Native FragmentPath must be the exact
service under its actor's generator/generator.early/generator.late runtime
directory, with empty systemd DropInPaths. This does not certify arbitrary
alternative Quadlet search roots or their configuration.
Account/home/shell/config and native identity restrictions match the credential
document. No extra host users, profiles or capabilities are provisioned.

## Modern mount ABI and ordering

Supported source ABI is **Linux x86_64, 64-bit pointers, 32-byte mount_attr** only.
The trusted system libc syscall boundary uses fixed UAPI numbers `open_tree=428`,
`move_mount=429`, `mount_setattr=442`. Unsupported ABI/kernel/policy refuses;
there is no syscall-number knob, mount(8), legacy mount(2), pathname mount target
or fallback. Syscall errors expose fixed reason tags, not raw diagnostics.

1. Complete identity, unit/source, container/freshness and reserve gates; acquire
   the Root-private marker lock/CAS authority; durably publish a v2 `claimed`
   operation with `cloneMountId:null`.
2. `open_tree(held_namespace_fd, "", AT_EMPTY_PATH|OPEN_TREE_CLONE|O_CLOEXEC)`.
   Verify the clone directory identity. Read its bounded
   `/proc/self/fdinfo/<tree-fd>` `mnt_id` (this is metadata, not a mount endpoint).
3. Durably publish that exact detached **cloneMountId before move_mount**. Reject
   an ID already in the mounted tree. A matching directory/path is not ownership
   of an arbitrary observed mount ID.
4. `mount_setattr(tree_fd, "", AT_EMPTY_PATH, {propagation:MS_PRIVATE}, 32)` on the
   detached clone. Recheck stopped/freshness/namespace authority and reserves.
5. `move_mount(tree_fd, "", held_namespace_fd, "",
   MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH)` (`0x44`). Confirm the attached
   mount ID is the durable preclaim, the namespace identity is unchanged and the
   shared parent's mount metadata has not changed.
6. Enforce private **again after attachment**, on the **same attached tree FD**,
   with `mount_setattr`. Attachment can inherit shared propagation despite step4.
   Recheck the FD mount ID and actual mountinfo privacy. Syscall success alone
   is not proof. Never change propagation using the old covering-directory FD.
7. Save actual private mount metadata, still `claimed`. Check/provision only fixed
   missing Rootful children; normalize ACL/UID/GID/mode only on newly created
   inodes through no-follow FDs. Check existing directories without repair. Create
   the engine last, after runroot/network directories, to limit partial layout.
8. Repeat canonical native gates under the verified pin, then publish `pinned`.
   Only then may the credential helper operate. Parent activation is separate.

In-process synchronous mount calls have a 30-second alarm deadline and retain
exclusive custody until they settle; an uninterruptible kernel wait can delay
signal delivery. There is no escaped worker able to attach after lock release.
Tree FDs are closed on all outcomes; an attached mount is not removed on failure.
No cleanup/unmount API, rollback or predecessor restart exists.

## Modes, unit gates and resource gates

| Mode | Contract |
|---|---|
| `apply` | First fresh pin, or verify complete same-boot state without repair; foreign/stacked mounts refuse. |
| `resume` | Exact same-boot claim only. An attached mount must have the durable clone ID; repair propagation on that exact mount, never rebind. A detached preclaim absent from the target requires review, not automatic allocation/replay. |
| `recheck` | Explicit boot/host-mount-namespace transition from a complete prior private pinned v2 claim, same stable namespace identity, held Root-only descendants, no current target mount; no Root-native store call until the new verified private pin. |
| `review-units` | Explicit same-boot evidence-only admission, complete exact current private pin and `--previous-evidence-sha256`; all exact scoped/native/kernel gates, no clone/rebind/child creation/permission or service changes. |
| `status`, `check` | Read-only complete-marker/kernel/child verification; no native execution, mount, initialization, ACL operation or repair. |

Parent closes owned boot/socket/timer/path/rotation triggers and prevents starts
through the entire maintenance interval. Stop only owned prototype units using
their supported lifecycle; resolve exact failed builder/container/overlay objects
through their owning lifecycle, preserving synthetic state and failed evidence.
This helper stops/removes/adopts nothing and refuses every descendant mount.
Parent preprovisions the Rootless home/config/engine/runroot. Missing config is
not a clean store. Existing Rootful runroot/network paths must be preprovisioned
before post-pin native inspection; missing volatile paths are not blanket repair
authority. Do not operate on excluded shared/legacy lanes.

For each actor, bounded fixed systemctl `list-units --all --plain --no-legend` and
`list-unit-files --no-legend` inventories cover dedicated-user `p0-*.service`
and `p0-*.timer/socket/path`, but reserved system-manager `p0-v2-*.service`
and `p0-v2-*.timer/socket/path`. Protected legacy system-manager `p0-*` services
are outside this authority. The names-only `list-unit-files --no-legend` query is
unfiltered and bounded, with exact scope filtering in memory. On the actual Host,
a filtered query with no matches returns exit1/empty stdout, also a possible
operational-failure shape; the helper never treats that ambiguous result as
absence. The unfiltered query must succeed with exit0; foreign names are not
reported, adopted or stopped. Unknown scoped services/triggers refuse; the sole
closed inactive ordinary relay exception is described below. Each reviewed Quadlet's `show --no-pager` must report loaded, inactive/failed, MainPID0,
empty ControlGroup/Job/TriggeredBy, and exact SourcePath/hash. No cgroup traversal
or global process fallback is used. Engines use only canonical explicit-store
`info --format json` and `ps --all --external --format json`; any container record
refuses. Even stopped/external objects count. No pull, container mutation or
network request is provided.

Native binaries must be trusted Root-owned single-link files with safe ancestors.
Rootless execution uses fixed `setpriv`, resolved UID/GID, cleared supplementary/
inheritable/ambient privileges and a freshly constructed environment. No native
FD inheritance is allowed. Native stdout <=256 KiB, stderr discarded, deadline30
seconds plus <=5 seconds cleanup of the exact newly created session/process group.
On an unsettled output/deadline failure, SIGKILL targets that group **before**
reaping its leader; no UID-global or unrelated-PID cleanup. Already settled
commands are not signalled. A cleanup timeout remains indeterminate, not proof
of no kernel-waiting descendant; Parent must reconcile its exact supervisor scope
before further affected operations. No raw output, exceptions,
locals or service source is reported. Kernel reads are bounded mountinfo (4 MiB),
boot_id and mount-namespace identities; the process must share PID1's host mount
namespace. Unrelated mounts outside the boundary are not native authority.

Available reserves: RAM16 GiB, root50 GiB, `/mnt/stack`100 GiB, actual `/var/lib`
staging1 GiB. Check before mutation, recheck before attach/propagation/each new
child. Stop only the affected unsafe operation; no global permission repair.

## Explicit same-boot evidence admission

Use `review-units` with the normal exact approved new evidence arguments plus
`--previous-evidence-sha256 <exact-current-marker-evidence-digest>`. This argument
is mandatory for this mode and forbidden elsewhere. The current pin must be
complete, private and exact, with unchanged boot/host mount namespace and stable
namespace identity. The existing private marker lock is exclusive and publication
uses its byte/stat CAS. There is no separate permit or caller path authority.

All actual scoped loaded/unit-file service/resource/trigger inventories must be
covered by the newly approved evidence; each declaration must have exact installed
source/hash/fragment and inactive/no-PID/job/cgroup state. Relays additionally
need the closed contract below. Repeat canonical no-container/authority gates
before publication. Unknown installed rows cannot be laundered by omitting them.
The existing marker stores only the previous digest, not a previous row list:
this is full *actual installed* inventory coverage, not invented historical row
retention. Properly uninstalled absent rows need not be fabricated.

Only `evidenceSha256` and its integrity checksum change. Owner/state/namespace,
boot/mount namespace, mount metadata and clone ID remain identical. No clone,
rebind, children, permissions, unit stop/start/reload or enablement occurs. Parent
holds its core operation interlock through this operation. `status`, `check`,
same-boot `apply`/`recheck`, `resume` and credential supply do not silently refresh.
Credential before/after-call marker-byte/file-identity guards remain independent:
even this legitimate metadata publication invalidates an in-flight old witness.

## Closed inactive ordinary relay evidence (E3)

Evidence v1 stays unchanged. Opt-in v2 has exactly `version:2`, `namespace`,
`units` (same closed actor/typed-Quadlet schema) and `relays`. Each relay is:

```json
{
  "id": "private-search",
  "address": "127.0.0.1",
  "port": 18200,
  "serviceSha256": "<64-lowercase-hex>",
  "socketSha256": "<64-lowercase-hex>",
  "resources": {"memoryMax": 67108864, "tasksMax": 32}
}
```

`resources` is optional; only those two positive nonboolean integers `<2^63` are
accepted. `port` is 1..65535, address a canonical literal loopback IPv4/IPv6 (no
DNS, zones, URL or wildcard). IDs follow closed lowercase identifiers; derived
unit names <=128 bytes and Unix socket path <=107 bytes. At most64 relays and256
total Rootful service rows; duplicates or Quadlet/relay name collisions refuse.
The caller supplies no paths, command, user, capability or environment.

Derive **only** `/etc/systemd/system/p0-v2-<id>.service` and `.socket`, with socket
`/run/p0-v2-upstreams/<id>/http.sock`. Root files must be single-link regular,
no-follow and non-group/other-writable under safe Root ancestors, exact approved
hash **and** exact independently reproduced closed renderer bytes. This binds the
fixed `/usr/lib/systemd/systemd-socket-proxyd --exit-idle-time=5min <literal>:<port>`,
`User/Group=p0-runtime`, exact hardening/limits, SocketUser=0/SocketGroup=0,0600/0710 modes
and RemoveOnStop. No extra directives, commands, alternate fragments, generic/
exact/dash-prefix drop-ins or Install/enablement clauses are admitted. The Root
helper never imports core/service Python. Parent owns proving the declared graph,
upstream-ready edge, binary compatibility and eventual transport. See the
read-only core contract [private-upstream-relays.md](private-upstream-relays.md).

Typed ordinary native observations require empty **SourcePath**, exact installed
**FragmentPath** (not generator output), empty DropInPaths, NeedDaemonReload=no.
Service: inactive/failed with dead/failed SubState, MainPID=ControlPID=0, empty
Job/ControlGroup, loaded User/Group=p0-runtime, TriggeredBy **exactly** the reviewed
socket. Socket: strictly inactive/dead, ControlPID=0, empty Job/ControlGroup and
TriggeredBy, Triggers exactly that service. A socket has a typed control PID, not
a fabricated service MainPID. Missing/extra/duplicate properties fail closed.
These exact native property/relationship semantics still need Parent qualification;
fixtures do not assert the Host returns them. Source files are re-read for exact
byte/stat identity after each observation.

Unit inactivity alone is not closure. Before/after pair inspection, check the
same network namespace as PID1 and bounded4 MiB `/proc/net/unix`: **any** row
naming the derived filesystem socket path refuses, irrespective of flags/state.
The socket path must also be absent; a stale filesystem socket is retained and
refused, never removed. If present, the fixed parent directories must have Root
custody; the relay directory must be Root0:G0,0710. Nothing is
created/repaired. Extra/active sockets, timers, paths, unrelated TriggeredBy or
listener rows still refuse. Protected legacy Root `p0-*` remains out of scope.

### Task06 DAC/FD correction

Parent Native06 independently demonstrated that a capless UID0 client cannot use
runtime-UID1004/0600 sockets, but can use Root0/0600. Native09 demonstrated the
fixed native UID1004 capless proxy forwarding via an **inherited** Root0:G0/0600
listener in a Root0:G0/0710 directory: the proxy does not need pathname access.
Failed07/08 fixture umask evidence remains retained; only newly created inodes
were normalized in09. These are not installed systemd/container proofs. The
corrected contract grants no DAC override and widens no socket mode. Rootful
container DropCapability=all rendering is Parent-owned, not a helper action.
See [host-relay-supply.md](host-relay-supply.md) for the separate fresh source
preparer; it neither changes namespace evidence nor activates these units.

## Active namespace marker v2 (evidence v1/v2, reports v1)

Authority is `/var/lib/p0-v2-namespace`, Root0700, containing only Root-owned
single-link0400 `active.json` <=256 KiB. Directory flock is exclusive for mutation,
shared for observation. This is active custody, not an experiment backup/archive.

```text
{
  version: 2, state: claimed|pinned, owner: <independent-128-bit-hex>,
  evidenceSha256: <approved-public-evidence-sha256>,
  namespace: {device:<st_dev>, inode:<st_ino>, filesystemId:<f_fsid>},
  bootId: <current-boot-UUID>,
  mountNamespace: {device:<nsfs-device>, inode:<host-mnt-namespace-inode>},
  cloneMountId: null|<exact-detached-ID-preclaimed-before-attach>,
  mount: null|{id,parent,device,root,target,options,optional,fsType,source},
  integrity: <private-full-record-corruption-check>
}
```

Every write CAS-compares previous bytes and device/inode/mode/UID/GID/link-count/
size/mtime/ctime, fsyncs a new0400 inode, atomically renames it and fsyncs authority.
Unknown/interrupted `.publish-*` evidence remains and refuses. The checksum is
not protection against Root. **Legacy v1 markers are not auto-migrated**: they
cannot retrospectively prove preclaimed clone ownership. Do not patch markers.

After an attach-before-private crash, explicit resume requires the same preclaimed
ID, stable namespace and boot/mount namespace. It reopens the exact mounted
namespace FD, checks its `mnt_id`, uses `open_tree` **without CLONE**, rechecks that
ID, then privatizes only that mount and verifies privacy. A covering FD refuses.
If private already succeeded, matching actual private state can be reconciled
without cloning/rebinding. Added tags, changed IDs/sources or unclaimed mounts
refuse; no path/inode-only recovery adoption is permitted.

A failed detached preclaim with no attached target remains preserved and requires
a separately reviewed Parent disposition. No force/reset/replay interface exists.
Incomplete children may similarly require review rather than permission repair.
On explicit supported `recheck`, preserve owner/stable identity; only after all
pre-pin gates clear, replace stale boot/mount observations and preclaim a new
clone ID. Never use an old boot's ID as authority. That transition or the explicit
same-boot `review-units` operation may update approved evidence; never implicitly.
Changed stable identity/device refuses. No ID/device
persistence across reboot is asserted.

Public reports expose bounded namespace/boot/mount identity, opaque owner,
`authorityStrategy:legacy-v2-unsafe-mutable-parent`, `secureAuthority:false`,
`protectedViewRequired:true`,
`mountStrategy:open-tree-setattr-move-mount-setattr`,
`existingRootfulRepinSupported:false`, `repinRequiresCompletePriorPin:true`,
`installationCertified:false`. Supported here means source interface, not native
or installed acceptance. Refusals are
fixed reason codes. No credential values/fingerprints, raw diagnostics or source.

## Retained evidence and remaining qualification

Parent private receipts remain independent, unchanged failed/successful evidence:

* `fd-path-native-01`: failures without canonical-first control; cause indeterminate.
* `fd-path-native-02`: canonical-first unprivileged empty fixture succeeds with
  literal graphroot; two inherited FD-number aliases fail. The proposed native
  mount-namespace explanation is **unproven**, not a policy/capability diagnosis.
* `host-bind-native-01`: legacy proc-FD self-bind fails.
* `host-bind-native-02` plus label correction: canonical private empty fixture
  bind/private works; second action was canonical, **not reopened-FD proof**.
* `host-bind-native-03`: modern clone/detached-private/attach works, but attached
  state is not private. This failure remains material evidence.
* `host-bind-native-04`: detached `mnt_id` readable, stable across exact-FD attach,
  same-tree-FD post-attach private succeeds and actual final PRIVATE=true.
  This qualifies those empty-fixture primitives only; no application data or real
  namespace was touched and no permissions/profiles/capabilities were weakened.

Remaining gates, not claims of success:

1. Parent independently stages/hashes/reviews this exact source and qualifies the
   whole helper on disposable owned empty fixtures: actual canonical native
   observations, marker fsync/CAS, private post-attach state and credential guard.
2. Qualify exact mounted-FD/no-CLONE recovery, fault points and post-reboot current
   observations through the actual supported lifecycle, not just primitive calls.
3. **Source-delivered E1, native unqualified:** explicit complete-owned populated
   boot recheck needs exact-source disposable fixture/fault qualification. Refuse
   unclaimed/claimed/foreign/incomplete stores; there is no automatic adoption,
   boot controller, store reset or assumed stable-ID persistence. The namespace
   record does not contain historical store inode IDs; trusted Root custody is
   part of the explicit security argument, not invented stored evidence.
4. **Conservative partial gap:** durable detached-ID claim without target attachment
   needs reviewed disposition; it is never overwritten to retry a fresh clone.
5. **Source-delivered E3/admission, native unqualified:** independently qualify
   the exact ordinary service/socket property sets, SourcePath/FragmentPath,
   inactive relationship reporting, private file custody/alternate fragment
   rejection, actual Unix listener closure, trusted proxy compatibility and
   evidence-only CAS transition. No builtin installation, graph/readiness or
   deployed transport proof is claimed. Never patch actual records or weaken the
   typed gates to bypass a native mismatch.
6. Actual selected installed acceptance remains Parent-owned and uncertified.

Source tests only:

```text
python3 -I -m unittest discover -s tests_v2 -p test_runtime_namespace.py -v
python3 -I -m unittest discover -s tests_v2 -p test_machine_credentials.py -v
```

Python fake syscalls/runners and new unprivileged private fixtures discriminate
canonical versus alias identity, actor privileges, preclaim-before-attach, shared
propagation inherited on attach, post-attach private verification, covering-FD
refusal, same-ID recovery, legacy/missing/forged/stale marker rejection, Rootful
freshness, replacement/symlink detection, exact unit/container gates, reserves,
CAS/locking, new-inode-only ACL handling and credential before/after-call guards.
No tests execute Root, native mount ABI, Podman/systemd, services, real credentials,
application-store operations, remote publication, models or guest/VM operations.
