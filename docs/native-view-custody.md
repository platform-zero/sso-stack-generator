# Critical07: protected native view, NOT a mutable-parent Host pin

**Security supersession, source-only work in progress.** Native10 falsified the
old custody premise: actual UID1000 in an older mount namespace renamed a Root0
bind-mounted dentry under its mutable parent; the Host mount target followed,
with the **same mount ID**. Host private propagation, exact-FD attachment and
before/after canonical identity checks alone do not exclude this attack. Earlier
APPLY/CHECK/ABI and task05 reports remain truthful narrowly scoped evidence, not
adversarial canonical-store custody acceptance. Do not rewrite/delete them.

Native11 independently demonstrated an independent Root-owned target parent plus
recursive protected projection preserving the **same canonical data path/inode**
despite the old-namespace physical-source rename. Protected-target rename denied.
Only empty fixtures were used/removed. It does not qualify a whole helper,
namespace persistence, manager transition, pause release, consumer or reboot.

## Immediate containment in current source

- Namespace helper `pin` in every mode and every engine observer refuses
  `protected-view-v3-integration-required` before filesystem/native work. Legacy
  geometry reports explicitly say `secureAuthority:false`, unsafe mutable parent,
  protected view required, repin unsupported. No v2 source status certifies custody.
- Credential `pinned_namespace` refuses before reading the old marker. Its old
  observation parser is forensic code only and is not the native authority path.
- Relay preparer `Authority` refuses before any private/target publication.
  Task06 Root0 socket/proxy1004/parentG0 corrections remain, but broad publication
  is **paused**, not delivered as an operational installer.
- These are SOURCE changes only. Worker changed no installed/staged helper,
  actual v2 record, permissions, PostgreSQL/runtime process, store or secret.
  Parent owns applying any reviewed containment to native orchestration.

Named legacy mechanism fixtures explicitly stub the new authorization boundary
only to retain ABI/CAS/claim/format regression coverage. Their passing counts are
**not** evidence that v2 is safe. Independent containment tests never stub it.
Credential native I/O/logic mocks likewise do not qualify real view authority.

## Fixed protected geometry

```text
/var/lib/p0-v2-view                    Root0, nonwritable trusted ancestors
  stack/                             Root0:G0,0711 (RootFS)
    p0-v2/                           independent Root0 covering target
                                     clone of exact held StackFS DATA directory
  authority/                         proposed Root0700 private v3 custody
/run/p0-v2-native-view/               Root0700
  namespace                          private persisted mount-namespace NSFS handle
```

The physical `/mnt/stack/p0-v2` is used only to obtain the exact reviewed original
**data directory FD** for explicit transition. Its mutable-parent pathname is
never future privileged native authority. Do not rename/copy/migrate project data
or change shared-parent ownership/mode/ACLs. The protected target is a different
dentry under Root-only parents; even actors in old namespaces cannot rename it.
The underlying data device/inode/FSID and literal native paths remain unchanged.

In the dedicated private native mount namespace, recursively project protected
`stack` over `/mnt/stack`, private before/after attachment. Host `/mnt/stack` stays
unchanged. Thus existing `/mnt/stack/p0-v2/{rootful,rootless}/engine`, libpod DB,
staticDir and volume metadata absolute paths need **no** path rewrite/migration.
Root-native prefix must enter only the exact Root-private verified NSFS handle,
then fixed OS Podman argv, no Host fallback or arbitrary Root command API.

Bind data identity and protected canonical target/mount geometry. Do **not** freeze
the mutable physical-source string printed as `mountinfo.root/source`: a physical
rename can alter those strings while the independent protected target and data
inode remain correct. A changed protected parent/data identity still refuses.

## Source implementation and explicit non-operational boundary

`ops/host-admin/provision-p0-v2-view.py` implements:

1. Strict prior-v2 complete checksum/hash/owner/data binding for **bootstrap prior
   ownership only**, never privileged v2 native access.
2. Strict v3/protected node/projection/NSFS-handle/manager/pause/unshare-witness
   schemas and current-observation comparisons. `complete()` is a **schema
   validator**, not an independent observation producer or certificate.
3. Bounded readonly Host protected-anchor/NSFS observation: safe Root ancestors,
   held O_PATH directory metadata, current boot/Host mount namespace, exact own
   protected mount/handle IDs/privacy, nsfs type and NS_GET_NSTYPE. No physical
   mutable source lookup, Podman or service import. This alone is insufficient
   for manager/pause/consumer authority.
4. Separate-source/target FD clone primitive with durable ID callback before
   move, detached private and **same attached tree FD** private, actual verification
   callbacks, and no removal on uncertainty. Duplicate FDs of the same source
   inode are refused as an independent target.
5. Recursive protected-parent projection primitive: AT_RECURSIVE clone, hold the
   cloned data-child FD, durably preclaim **both** parent/data detached mount IDs,
   recursive private before/after exact move. Actual ABI remains unqualified.
6. Source transition state machine and fixed unprivileged actual-unshare program.
7. Physical capacity checks through held bound DATA FD, not shadow-parent RootFS.
8. Independent `ViewStore` private Root0700/0400 ledger: nonblocking exclusive
   flock, byte/stat and held-directory CAS, fsync/rename/fsync, exact O_EXCL prior-v2
   retention and hash/custody revalidation. Interrupted fixed `.publish-active`
   remains and refuses. Fixed old-marker read returns exact SHA-bound bytes plus
   file snapshot, never edits the old marker. These file mechanisms have new
   unprivileged mapped-ownership fixture tests, not production Root qualification.

**Production `ClosedHost.preflight` and CLI plan/transition/resume currently
refuse `native-manager-pause-gates-unqualified` before source/old-record access or
any mkdir/publication. `root_prefix` also always refuses consumer integration.**
`proposed_root_prefix` is a pure argv contract only; it never executes or authorizes
one. No actual Root private v3 record is written, no manager drop-in is published,
no pause is signalled and no native namespace is created by this revision.

This deliberate boundary prevents a self-consistent fake observation/receipt from
becoming Root authority. Do not replace it with an input flag or treat a fixture
backend as production. Before enabling a production path, implement/review the
exact private staged Root0400/0700 self-and-independent hash bootstrap, locks/CAS,
trusted observations and qualified backend. Current CLI arguments describe only
the intended closed interface; refusal happens before they could grant authority.

## Proposed explicit v3 transition state machine

One Parent operation interlock, Root-private exclusive lock and byte/stat CAS:

| State | Required durable fact before subsequent effect |
|---|---|
| `claimed` | exact expected previous complete-v2 raw SHA/file identity/owner, approved stable data identity; prior bytes retained independently Root0400, old active record never edited |
| `anchor-preclaimed` | newly prepared independent Root target/parent/held-data identities plus exact detached clone ID **before move** |
| `anchor-private` | observed independent target is exact data inode/FSID, correct private mount geometry; no Root-native store call |
| `native-namespace-claimed` | exact new boot/namespace worker/handle preparation claim before namespace persistence/projection effects |
| `native-view-bound` | Root-private NSFS inode/type/mount and current private recursive parent/data projection independently observed |
| `manager-pending` | native view bound but manager/pause/actual-unshare still absent; **no native authority** |
| `complete` | all exact manager/private-view, pause closure, actual-unshare and consumer before/after observations independently qualified; not published by current implementation |

`ViewStore` implements the private file/CAS primitives; the fake test backend
models kernel/manager facts, not a production Root observer. Trusted staged
bootstrap/previous-snapshot binding and production store/backend wiring remain
closed. The private ledger's parent must already have safe Root custody; creating
that private authority container is not permission to adopt a matching data mount
target. Current transition implementation stops at manager-pending
with nativeAuthority=false. Existing/partial states refuse automatic continuation
or new-boot replay pending reviewed exact reconciliation. Detached/preclaim-absent
or uncertain handles/effects remain, not deleted/reset/adopted. Complete prior
custody may eventually support explicit fresh per-boot handles; that backend and
boot reconciliation are **not implemented**, and stable IDs changing must refuse.

Actual namespace creation/persistence needs exact qualification: unshare only its
new namespace, privatize recursively there before projecting, persist an exact
owned namespace inode/NSFS handle with preclaims, retain supervision/lock until
all child effects settle, verify projection before/after native entry. No escaped
worker, global mount operation, arbitrary proc/PID path or Root exec fallback.
Do not invent a working namespace-persistence ABI from tests or Native11.

## Dedicated manager and Rootful unit contract (Parent integration)

Parent owns rendering/lifecycle:

```ini
[Service]
BindPaths=/var/lib/p0-v2-view/stack:/mnt/stack
PrivateMounts=yes
```

Rootful services use this projection. Only new dedicated `user@1004.service` may
receive the fixed Root-owned closed drop-in
`/etc/systemd/system/user@1004.service.d/50-p0-v2-view.conf`. No gerald manager,
legacy Root p0-* unit, existing authored/unrelated drop-in or shared lane is altered.
Verify actual manager template fragment/source hash, UID/GID, stopped PID0/empty
cgroup/job, old state and drop-in inventory **before** new publication. Existing
foreign files refuse; do not overwrite/normalize them. No default activation or
restart is authorized. Current source provides stopped schema checks, not this
publication implementation or actual template-path qualification.

Parent actor commands must use a `systemd-run --user` transient **service** inheriting
the manager view. `--scope` inherits the caller's unsafe namespace and is forbidden.
Manager/Rootful/native-helper namespaces may have different mount IDs; each must
prove the same protected parent/data identity and private geometry, not reuse one
namespace's IDs as another's authority. Manager actual process/namespace/cgroup/
source-before-after observer is a remaining native/source integration cell.

## Old pause process and actual-unshare gate

A correct client view is not enough: Podman may reexec into its old cached pause
mount namespace. No `system migrate`, global kill/prune, automatic adoption or
integer-PID signal. Missing PID-file does not prove pause absence.

Required reviewed protocol: exact stopped owned services/resources and actual
no-container/native metadata under independently proved engine custody, then exact
owned PID-file identity, process UID/GID/executable qualification, starttime, boot,
user+mount namespaces, exact nonempty own cgroup and held pidfd identity. Only an
explicit future exact pidfd-stop operation may release that known old cache,
followed by absence/identity guards. Source currently **refuses** an unqualified
pause executable profile and implements no signaling. We do not guess whether
this Host's pause executable is Podman/catatonit, signal unrelated processes or
infer container absence through an unproved old path. The actual safe inventory/
release/supervision sequence needs Parent qualification; it remains a precise gap.

The fixed metadata-only `UNSHARE_PROGRAM` must run inside **actual Podman unshare**
before every ordinary-secret/value/store/volume mutation. It checks O_PATH held
protected parent/data/engine device/inode/FSID/modes and exact UID/GID maps against
a Root-verified witness. No service import, exec, value or native store command.
It emits a bounded fixed ops frame; it is not itself a mutation permit. Native
consumer integration must bind each command to the verified effective pause/view
and recheck before/after; a successful separate client probe cannot certify a
later Podman reexec or different pause namespace. Parent owns volumecontext and
INODE_PROGRAM integration; Worker has not changed them.

**Overflow UID hazard:** Host UID0 can appear as65534 inside Rootless unshare,
just as Host mutable-parent UID1000 can. Checking raw UID alone would accept both.
The guard binds protected parent/data inode/FSID and exact maps; maps namespace0
to trusted runtime1004, never Host0; derives Host0's mapped/overflow owner from
actual maps and kernel overflow IDs. Tests explicitly reject a mutable-parent
inode despite identical raw overflow UID and unchanged data/mount IDs. O_PATH
fstatvfs/map behavior and exact Rootless native command/reexec semantics still
need actual qualification before mutation can be enabled.

## Reserves and preservation

Physical StackFS100 GiB is checked on the bound DATA directory or its held FD.
`/mnt/stack` in the protected view is RootFS and must **not** be used for that floor.
RootFS50 GiB, RAM16 GiB and actual staging1 GiB remain independent. Existing helper
source reserve paths now name the data child; its native authority remains blocked.

No actual old record/source hash, data/DB path, credentials, shared-parent ACL/mode,
PG/runtime state, original lane or installation was touched. No transfer, archive,
backup/snapshot, production restart, provider/model/device/paid/quota operation or
guest operation. Both protected Keykeeper refusals remain stopped. Full selected
installed acceptance remains the goal, not a claim from this source checkpoint.

Source-only regressions:

```text
python3 -I -m unittest discover -s tests_v2 -p test_native_view.py -v
python3 -I -m unittest discover -s tests_v2 -p test_runtime_namespace.py -v
python3 -I -m unittest discover -s tests_v2 -p test_machine_credentials.py -v
python3 -I -m unittest discover -s tests_v2 -p test_host_relays.py -v
```
