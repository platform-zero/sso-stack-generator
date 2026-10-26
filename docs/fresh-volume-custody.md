# Fresh Rootless named-volume custody (source-only)

`p0core/volumes.py` is a generic unprivileged component for **new declared** local
named volumes. It is not application inventory, permission repair, data adoption,
cleanup, migration or a Root helper. Never import/execute it as Host Root. It
creates no account, container, mount, service or scheduler. It does not alter the
task03 helpers. Parent owns manifest/render/lifecycle/Runner/CLI integration and
actual native qualification; this component is not yet an installed interface.

The existing PostgreSQL volume has no custody declaration. **Do not pass it here**,
adopt it because it looks empty, add ownership labels or chmod/chown its data.
Old/foreign volumes refuse even if they have matching mode, options or contents.

## Early integration contract

A separate Parent interface proposal accompanies this component. The following
describes the implemented component, not fields already admitted by
Parent's manifest schema:

```json
{"kind":"volume","source":"consumer-journal","target":"/private-journal",
 "custody":{"uid":1000,"gid":1000,"mode":"0700"}}
```

`uid` and `gid` are exact integers0..65535, not booleans. `mode` is exactly
`"0700"` or `"0750"`, never an integer, loose octal string, set-ID or world-access
mode. Mode0750 additionally requires no extended access/default POSIX ACL on
this inode; unknown ACL observation refuses, never repairs. Mode0700 masks all
nonowner ACL access. No custom path, driver, option, command, generator or recursive operation.
Parent must reject Rootful use, conflicting shared definitions and mixed declared/
undeclared references before any publication. A declaration is consumer-owned;
there is no app-name table. All references to the same resource require the same
semantic custody. No declaration means existing lifecycle behavior, not implicit
permission to adopt or initialize existing data.

Component API:

```text
VolumeCustody(preprovisioned_private_directory, adapter)
    .ensure(resource, custody, resume=False) -> prepared admission frame
NativeAdapter(runtime)  # requires actual non-Root p0-runtime identity
```

`resource` is a bounded lowercase hyphenated identifier <=48 characters; native
name is `p0-<resource>`. Production mountpoint is derived **only** as
`/mnt/stack/p0-v2/rootless/engine/volumes/p0-<resource>/_data`. Graphroot flags are
literal canonical paths, never inherited-FD aliases. The definition hash covers
schemaVersion1, runtime rootless, resource/nativeName, driver local, options empty
and exact custody. It identifies noncredential resource semantics, not data.

### Parent Runner/Runtime additions (not implemented in shared files here)

* Extend the existing single bounded Runner with keyword-only `pass_fds=()`;
  admit only empty tuple or **one** exact-int valid directory FD. Keep
  `close_fds=True`, fresh clean environment/cwd, output limits, per-call deadline
  and cancellation/reaping of its own process group. No shell or alternative
  subprocess runner. No blanket FD relaxation in credential/mount helpers.
* `runtime.run(arguments, timeout=30, input_bytes=None, pass_fds=()) -> bytes`
  delegates to that Runner. Component checks response <=256 KiB, JSON bounds and
  uses one fixed unshare command. Input <=4096 bytes. Parent's tighter bounds may
  reject earlier, never allow unbounded execution.
* Add `runtime.verify_volume_context() -> stable JSON witness`, after actual
  p0-runtime UID/GID, canonical graphroot, overlay/runroot, home/cwd/storage.conf,
  graph directory and mount-namespace identity checks. Required checked keys are
  `graphRoot`, `uid`, `gid`; the witness must additionally bind the actual context
  checks above, including available reserve checks on every call. Bind immutable
  engine identity/custody, not its mutable directory mtime. The adapter snapshots
  canonical bytes to avoid mutable-object
  aliasing and compares around **every** native call. A fake witness is not proof.
* Parent verifies reserves and holds its operation/activation interlock throughout
  preparation. No concurrent container starts or materialization. The component
  observes users but is not a systemd activation lock.
* Prepare/admit before publishing volume/container Quadlets. Preserve the exact
  returned ownership labels, driver/local empty options and custody; do not let
  Quadlet options, copy-up, `:U` recursive chown or another initializer override
  them. Existing native row/identity must remain unchanged during publication.
* No CLI or automatic resume is supplied. Parent must expose explicit reviewed
  continuation rather than using ordinary install as a force/reset mechanism.

## Custody journal and native identity

The caller preprovisions a dedicated private directory, runtime UID/GID-owned0700 with
non-symlink Root/runtime-owned ancestors and no group/other writes. It must not
live beneath the shared writable ancestor. Only <=512 `p0-<resource>.json`
runtime UID/GID-owned single-link0600 files may exist. Every existing record is
schema/definition/hash validated and must bind its own native-name filename;
a second filename cannot claim the same native resource. Directory flock is exclusive and
nonblocking. Unknown/legacy filenames, symlinks, wrong modes, hardlinks and stale
`.publish` files refuse and remain. No initialization of this directory by the
component, archive/snapshot, automatic cleanup or permission repair.

Each record has exactly:

```text
version:1, definition, definitionSha256, nonce:<independent random128-bit hex>,
state:claimed|bound|chmod-claimed|chmod-done|chown-claimed|prepared,
native:null|<exact native identity>, inode:null|{device,inode},
maps:null|{uidMap,gidMap}, initial:null|{uid,gid,mode}, integrity
```

Integrity is an internal corruption check, not protection against the trusted
runtime actor rewriting its own state. Each write compares previous exact bytes
and inode/device/UID/GID/mode/nlink/size/mtime/ctime, writes/fsyncs a new0600 inode,
CAS-checks again, atomically renames and fsyncs the directory. Reopened directory
identity/custody is checked so replacing the lock directory is not continuation.
The fixed exclusive `.publish` name uses O_EXCL: failure remains evidence and
cannot be overwritten. Resume draws **no new entropy**, including filenames.

Native labels bind managed=v2, resource, semantic intent hash and preclaimed
nonce. Before create, verify native absence, no partial canonical volume path,
no mount/submount and no users, then **durably save the claim before create**.
No existing-claim path ever calls native create again. An uncertain create can
leave a native row, partial filesystem state, or neither. Native-row absence
alone is not proof of no effects: continuation without the row always refuses,
whether or not a partial path is visible. No fresh-name retry, delete, reset or
label adoption is provided.

Claimed-with-row continuation needs explicit `resume=True`, exact labels/nonce/
definition and native metadata, fresh emptiness and no-users proof. Required
native fields: Name, CreatedAt (valid timezone timestamp), Driver local, Options
exactly `{}`, Labels exact, Mountpoint exact, MountCount known nonnegative and0
while fresh. Native UID/GID null/options are **not** physical ownership evidence.
Unknown/missing/unsupported metadata refuses. No NativeVolumeID is invented when
Podman supplies none. Bound native identity excludes mutable MountCount; it
includes creation timestamp and all other required fields. Native metadata plus
held `_data` device/inode and mapping/initial custody are durable before effects.

## Held inode and namespace mapping protocol

Host `_data` traversal uses no-follow directory FDs for **every component** and
holds O_PATH. That allows immutable-stat rechecks after namespace1000 ownership
maps away from Host p0-runtime and mode0700 denies Host read access. No chmod/chown
is applied through a pathname or `/proc/self/fd` symlink.

One reviewed fixed command, via Parent's bounded Runner:

```text
/usr/bin/podman <fixed canonical root/runroot/overlay flags> unshare \
  /usr/bin/python3 -I -c <source-owned INODE_PROGRAM constant>
```

Only the exact held directory FD is inherited. Bounded stdin carries a closed
request (action, fd, identity, before, desired, fresh, resource, maps); it is not
code. Actions are only probe/fchmod/fchown on this inode. The stdlib program opens
`.` relative to the held FD to acquire a readable directory FD inside the
unprivileged user namespace and verifies both FD identities. It also no-follow
opens the derived canonical `_data` **in the child namespace** before/after and
requires it to name the held inode: joining another namespace does not authorize
an alias bypass. It refuses mounts of the volume-store directory, selected volume
directory, data-target or data descendants in that namespace, before/after effects.

The program captures actual namespace stat and uid_map/gid_map. Parent controller
validates disjoint bounded map ranges, no Host0 mapping, namespace0 mapping to
resolved Host runtime UID/GID and coverage of requested IDs. It compares explicit
Host fstat UID/GID/mode against translated namespace stat. Maps are frozen in the
record and matched **inside the program before an effect** and after readback.
For example, `[0,1004,1],[1,362144,65536]` maps namespace1000 to Host363143; simply
seeing namespace1000 or an option uid=1000 is insufficient.

Fresh initial namespace ownership must be0:0, mode0755 or0700. No arbitrary owner/
mode normalization is allowed. Transition sequence:

1. `claimed` -> native/held inode/maps/initial snapshot -> durable `bound`.
2. Persist `chmod-claimed` before fixed `os.fchmod(readable_fd, desired_mode)`.
   Verify namespace/Host readback, canonical/held identity, native identity,
   emptiness and no users; persist `chmod-done`.
3. Persist `chown-claimed` before fixed `os.fchown(readable_fd, uid, gid)`.
   Again verify independently probed namespace/Host mapping and all freshness
   gates; publish `prepared` only after success.

Explicit resume admits only known direct states: initial or restricted-root mode
around chmod, restricted root0:0 or exact desired UID/GID/mode around chown. An
already-observed exact outcome is reconciled without repeating its syscall.
Partial owner pairs, unexpected modes, map changes, successful output without
actual readback or permission errors do not authorize repair. All failed claims
remain. There is no recursive traversal/chmod/chown of data.

Fresh probes check emptiness before/after each effect without printing names.
Host and child mountinfo are bounded; target/descendant mounts refuse. Native
`ps --all --external --format json` includes stopped objects. Each known ID needs
successful inspect and known Mounts. Any target volume name/source or ancestor/
descendant source overlap refuses. Unknown external builders/inspect failures/
mount kinds refuse. **Conservative bind limitation:** any container bind source
is treated as unknown while fresh; lexical non-overlap cannot exclude a bind or
symlink alias, and this component does not walk arbitrary Host bind sources to
prove otherwise. Known unrelated native volume/tmpfs mounts can pass. Unrelated volumes also need
exact canonical mountpoints, a fresh native inspect proving local driver/empty
options (not a bind-device option), and no mount alias at their source. Parent
should prepare fresh volumes before activating bind-mounted consumers; broadening
this gate needs a separate safe typed proof, not an arbitrary-path exception.

## Prepared data is not fresh data

A prepared volume can contain real data and can have active native users. Recheck
requires the same semantic policy, nonce, native creation/labels/options/path,
held `_data` device/inode, immutable maps and exact mapped UID/GID/mode. It does
**not** scan contents, demand emptiness, require no users, write the record or
perform inode effects. Changed ownership/inode/custody refuses without repair.
Mount/submount ambiguity still refuses. This read-only recheck is not a backup,
health check or installed acceptance proof.

The admission frame contains version, resource/native name, state, noncredential
definition hash, ownership labels and `installationCertified:false`. No data,
credential, value fingerprint, raw logs, locals or exception strings. Unknown
operation exceptions are reduced to a fixed indeterminate tag at `ensure`;
claims remain for review. Parent owns outer CLI error/cancellation framing.

## Evidence and remaining gates

Parent `volume-custody-native-01.json` retains the failed ownership assumption:
uid/gid options (even mode option) produce Host1004 mode0755 and null native IDs.
`volume-custody-native-02.json` retains positive held-FD unprivileged unshare
mapping to namespace1000:1000:0700 / Host363143. These qualify only new empty
fixtures. The qualification program used fixed chmod/chown/stat commands on a
held proc-FD endpoint; it did **not** execute this exact O_PATH/reopen/direct
fchmod/fchown stdlib program or the private journal/lifecycle. Earlier graphroot
FD-alias failures remain material; no alias graphroot is reintroduced here.

Remaining Parent gates:

* Implement/review the narrow Runner pass_fds + context witness interface and
  manifest conflicts, immutable publication, reserves and activation interlock.
* Qualify actual native metadata shapes/options/CreatedAt/MountCount, namespace
  map/canonical identity, O_PATH inheritance/reopen, direct FD effects and Host
  readback on disposable **new empty owned** fixtures. Unsupported native facts
  refuse, not defaults. Do not run this component on existing application data.
* Qualify actual crash/resume/publication/CAS/cancellation and prepared populated
  recheck through supported native lifecycle. No forced removal is a clean stop.
* Existing data, unknown/foreign or absent-row claims need reviewed disposition;
  no component deletion/reset/adoption is authorized.
* Parent's populated Rootful boot E1 and exact inactive relay/source/trigger E3,
  PG privacy, volume consumer integration and installed acceptance remain separate.
  No refused Keykeeper operation is resumed. No whole-product completion claim.

Source-only test command:

```text
python3 -I -m unittest discover -s tests_v2 -p test_volumes.py -v
```

Tests use newly owned unprivileged temporary fixtures and fake native mappings/
metadata/process adapters. Physical inode/record/lock/CAS tests use those fixtures;
Host mapped ownership/stat is deliberately virtualized, never claimed as kernel
proof. The fixed unshare program is AST-checked, not executed. No Root, Podman,
unshare, app store, protected file, service, model, remote publication or actual
mapped chown occurs in tests. All failed logs and prior evidence are retained.
