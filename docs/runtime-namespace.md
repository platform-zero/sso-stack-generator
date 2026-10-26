# P0 v2 pinned data namespace: bounded Root authority

`ops/host-admin/provision-p0-v2-namespace.py` is a standalone stdlib helper, not a
dispatcher, controller, general mount manager or cleanup tool. Its only mount
target is the **existing new** `/mnt/stack/p0-v2`. It accepts no caller commands,
devices, capabilities, profiles, arbitrary mount paths or teardown switches.
Root never imports service/core/user Python or the credential helper. The latter
independently verifies the same namespace-marker contract.

**Source-only qualification.** The modern primitive ABI has separate Parent
empty-fixture receipts; those are not helper, lifecycle or installed acceptance.
Do not use this source revision against application stores before Parent's private
Root review and qualification. Initialized unpinned Rootful stores are explicitly
unsupported; see the remaining gates below.

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
canonical kernel mountpoint. A non-Root ancestor writer cannot replace that
mountpoint. Root and the kernel remain trusted; this is not protection against
Root unmounting it. A pre-attachment rename causes refusal, not privileged native
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

**Rootful pre-pin circularity is resolved conservatively**, not by running Host
Root Podman through the shared parent: the reviewed Rootful unit list must be
empty, native unit inventories must agree, and no-follow inspection requires the
Rootful actor/engine to be absent or correctly Root-owned0700 and **empty**. The
exact absence/empty-inode witness must remain unchanged around observations.
Existing metadata, installed Rootful units, symlinks or alien custody refuse
before any native store call or mount/marker effect. First pin must precede
Rootful unit publication/store initialization. The helper never deletes metadata
or moves a store to manufacture freshness.

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
are explicit, each <=64 unique `p0-[a-z][a-z0-9]*(?:-[a-z0-9]+)*.service` names
<=96 characters. Empty means no installed units, not permission to ignore them.
Sources are fixed `<unit-stem>.container` paths under
`/var/lib/p0-runtime/.config/containers/systemd` or `/etc/containers/systemd`,
with the exact reviewed hash. No caller SourcePath or source execution is allowed.
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
| `recheck` | Explicit boot/host-mount-namespace transition, same approved stable directory identity, no current target mount, all gates again. **Only absent/empty uninitialized Rootful state with no Rootful units is supported.** |
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
`list-unit-files --no-legend` inventories cover `p0-*.service` and
`p0-*.timer/socket/path`. Unknown services and all such triggers refuse. Each
reviewed unit's `show --no-pager` must report loaded, inactive/failed, MainPID0,
empty ControlGroup/Job/TriggeredBy, and exact SourcePath/hash. No cgroup traversal
or global process fallback is used. Engines use only canonical explicit-store
`info --format json` and `ps --all --external --format json`; any container record
refuses. Even stopped/external objects count. No pull, container mutation or
network request is provided.

Native binaries must be trusted Root-owned single-link files with safe ancestors.
Rootless execution uses fixed `setpriv`, resolved UID/GID, cleared supplementary/
inheritable/ambient privileges and a freshly constructed environment. No native
FD inheritance is allowed. Native stdout <=256 KiB, stderr discarded, deadline30
seconds plus <=5 seconds cleanup of the exact child. No raw output, exceptions,
locals or service source is reported. Kernel reads are bounded mountinfo (4 MiB),
boot_id and mount-namespace identities; the process must share PID1's host mount
namespace. Unrelated mounts outside the boundary are not native authority.

Available reserves: RAM16 GiB, root50 GiB, `/mnt/stack`100 GiB, actual `/var/lib`
staging1 GiB. Check before mutation, recheck before attach/propagation/each new
child. Stop only the affected unsafe operation; no global permission repair.

## Active namespace marker v2 (evidence and reports remain v1)

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
clone ID. Never use an old boot's ID as authority. Only that transition may refresh
approved unit evidence. Changed stable identity/device refuses. No ID/device
persistence across reboot is asserted.

Public reports expose bounded namespace/boot/mount identity, opaque owner,
`authorityStrategy:canonical-after-verified-pin`,
`mountStrategy:open-tree-setattr-move-mount-setattr`,
`existingRootfulRepinSupported:false`, `installationCertified:false`. Refusals are
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
3. **Engineering gap:** initialized Rootful stores or installed Rootful units after
   pin loss/reboot are refused (`rootful-unpinned-existing-store-unsupported` or
   `rootful-unpinned-units-unsupported`). No full automatic existing-store repin,
   ordinary populated Rootful boot recovery or production adoption is delivered.
   Post-pin `info` itself may initialize the store, so even an otherwise empty
   first install can later enter this unsupported cell.
4. **Conservative partial gap:** durable detached-ID claim without target attachment
   needs reviewed disposition; it is never overwritten to retry a fresh clone.
5. **Future transport follow-up (not installed):** Source03 recognizes only
   reviewed `.container` service sources and requires empty socket-file/unit
   inventories and empty `TriggeredBy`. It therefore intentionally rejects later
   maintenance/recheck after Parent's proposed `http-socket-relay` installation,
   even if the relay is inactive. Supporting that builtin requires a new closed,
   typed source contract, not blanket socket/trigger exceptions:
   * distinguish system-manager native Host units from user/system Quadlets and
     from container runtime actor; do not infer a `.container` source for a native
     `.service`;
   * derive and independently hash/custody-verify the immutable exact
     `/etc/systemd/system/p0-<id>.socket` and `.service` source/fragment paths;
     verify actual typed SourcePath/FragmentPath semantics and reject alternate
     fragments, drop-ins, extra units or relationships;
   * require the declared socket inactive/closed before namespace maintenance,
     with no live listener, pending job or unrelated activation trigger; an
     inactive socket file is not proof that its listener is closed;
   * permit only the exact reviewed **inactive** socket-to-service `TriggeredBy`
     relation while keeping the service inactive/failed, MainPID0, empty job and
     cgroup gates; unknown/active sockets or extra trigger relations still refuse;
   * bind service `User=p0-runtime` (no new Host account), fixed trusted
     `/usr/lib/systemd/systemd-socket-proxyd` and the declared Rootless loopback
     HTTP endpoint. No arbitrary native command, container Host networking or
     admin socket is authorized.
   This is a precise unimplemented acceptance cell, not permission for Parent to
   patch active evidence or bypass the current strict gates.
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
