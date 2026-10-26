# Closed inactive Host relay source supply

> **CRITICAL07 / TASK06 PAUSED:** the old v2 mutable-parent private-bind premise
> was falsified by Native10. Current `Authority` refuses
> `protected-view-v3-integration-required` before any private/target publication.
> The source state machine and fixtures below are intermediate mechanisms, not an
> operational installer or native acceptance. Root0 socket/proxy1004/parentG0 DAC
> correction remains. No actual publication occurred. Protected view/native
> namespace/manager/pause/actual-unshare integration is required first; see
> [native-view-custody.md](native-view-custody.md).

`ops/host-admin/provision-p0-v2-relays.py` is a standalone stdlib Root source
preparer, **not** a dispatcher, activation controller, storage provisioner or
installed acceptance harness. Task06 qualification is source-only. It imports
neither core/service Python nor another helper. Its independent namespace,
unit-source, native-runner and renderer validation must be reviewed as privileged
source in its own right, not trusted because another helper passed tests.

## Exact DAC contract

Socket: Root0:G0,0600. Per-relay directory: Root0:G0,0710. Proxy service:
`User/Group=p0-runtime`, empty capabilities and NoNewPrivileges. Rootless providers
and their existing entrypoint requirements are unchanged. Parent owns new Rootful
container `DropCapability=all` rendering; this helper changes no application
profile or capabilities.

Parent Native06 proved a UID0 **all-capabilities-zero** client cannot connect to
runtime UID1004/0600 but can connect to Root0/0600. Native09 independently observed
the fixed native proxy UID/GID1004, zero capabilities and native executable,
receiving a Root0/0600 listener FD in Root0:G0/0710 and forwarding synthetic HTTP
to a capless Root client, then cleanly exiting. The proxy does not need pathname
access to its inherited FD. Failed07/08 fixture umask evidence remains retained;
09 normalized only its newly created inode. Those receipts do **not** qualify
installed systemd properties, automatic directory ownership or container transport.
No DAC override, wider socket mode or configurable socket-owner API is provided.

## Parent approval and private execution

Parent reviews/pins exact committed source. Stage the exact single-link Root0400
file beneath a new Root0700 executable private `/var/lib` directory, with safe
Root ancestors. Independently hash the staged inode **before** trusted
`/usr/bin/python3 -I`, from a clean privileged environment (including no preload
injection). The self SHA check is defense in depth, not bootstrap trust. No
execution from editable checkouts, noexec `/run`, service images or user imports.
Core dumps are disabled; non-isolated CLI refuses before filesystem imports.

Documentation-only command shape:

```text
/usr/bin/python3 -I <privately-staged-helper> <apply|resume|rematerialize|status> \
  --helper-sha256 <reviewed-source-sha256> \
  --intent <absolute-approved-nonsecret-json> --intent-sha256 <exact-byte-sha256> \
  --evidence <absolute-current-approved-namespace-evidence> \
  --evidence-sha256 <exact-byte-sha256> --input-uid <approved-uid-at-least-1000> \
  --parent-interlock-held
```

The final flag is mandatory for mutations; it is an explicit Parent assertion,
**not** a lock acquired or invented permit. Parent must actually hold its state/
activation interlock throughout publication/reload/review and prevent starts.
Inputs are bounded256 KiB, exact approved owner, single-link regular no-follow,
non-group/other-writable, with safe Root/approved-UID ancestors. No credentials.
Parent verifies catalog/provider/readiness graph and endpoint selection separately.
This helper offers no catalog loader, URL, binary, template, arbitrary path,
engine option, Host-network, capability or administrative-socket API.

Closed intent (all hashes are exact independently derived source bytes):

```json
{
  "version": 1,
  "relays": [{
    "id": "search-http", "address": "127.0.0.1", "port": 18200,
    "serviceSha256": "<64-lowercase-hex>",
    "socketSha256": "<64-lowercase-hex>",
    "resources": {"memoryMax": 67108864, "tasksMax": 32}
  }]
}
```

One initial batch of1..64 unique bounded lowercase IDs. Address is canonical
literal loopback IPv4/IPv6, no DNS/zones/wildcards. Port1..65535. Resources optional,
only positive nonboolean memoryMax/tasksMax `<2^63`. No extra/duplicate JSON keys
or nonfinite constants. Independent exact closed renderer bytes **and** their
approved hashes must agree. SocketUser/Group0 is literal, not input. Names only
`p0-v2-<id>.service/.socket`, fixed trusted proxy command and hardening identical
to the reviewed [private-upstream-relays.md](private-upstream-relays.md) contract.
Protected legacy system-manager `p0-*` is outside this scope.

Existing namespace evidence v1/v2 is a separate explicit approved file. Its digest
must equal the actual Root-private complete current pinned marker; stable namespace,
boot/host mount namespace, private propagation, durable clone ID, ancestors and
kernel metadata are independently checked. Hold the namespace marker shared lock,
byte/stat witness and held namespace FD, checking before/after gates/effects. No
namespace mount, evidence refresh or application-store access is performed.

## Fresh source publication and custody

Fixed private authority `/var/lib/p0-v2-relays`, Root0700, contains only Root0400
single-link `active.json` <=256 KiB. Exclusive nonblocking flock and exact prior
byte/stat CAS protect checksum-bound version1 schema/intent/owner/namespace/boot/
object records. Unknown or interrupted private `.publish-*` entries remain and
refuse. One active batch only: later different batches/configuration require a
separate future reviewed protocol, **not** incremental matching-file adoption.

Publish targets:

| Object | Fixed path / custody |
|---|---|
| shared new base | `/run/p0-v2-upstreams`, Root0:G0,0711 |
| per-ID directory | `/run/p0-v2-upstreams/<id>`, Root0:G0,0710 |
| service/socket source | `/etc/systemd/system/p0-v2-<id>.{service,socket}`, Root0:G0,0400 |

First apply requires **all targets absent**, even matching Root-owned bytes or
empty directories. Native loaded/unit-file/trigger inventories must cover the
entire reserved system-manager scope and dedicated runtime user's `p0-*` scope
under the current approved evidence. Unknown/active units, jobs, PIDs, cgroups,
foreign fragments, exact/generic/dash-prefix drop-ins and alternate sources refuse.
Same PID1 network namespace and bounded4 MiB `/proc/net/unix` must show no derived
Unix socket row, with no stale socket path. A source file is not listener closure.

Persist the private global claim **before any target-directory/file effect**.
Each object then follows:

1. `planned`: no preparation attempted; target and temp must be absent.
2. Persist `prepare-claimed` **before** exclusive same-parent deterministic
   `.p0-relay-<nonce>-<key>` creation. No unknown temp is deleted or reused.
3. Through the newly created no-follow inode FD only, set Root0:G0, exact mode
   independent of caller umask, remove default ACL on fresh directories, write
   exact source, fsync inode and held parent. Never chmod/chown existing data.
4. Persist `prepared` with device/inode/UID/GID/mode; recheck source bytes and
   no stale nodes, native gates, pin and reserves.
5. Persist `publish-claimed`, then atomic same-parent libc `renameat2` with
   **RENAME_NOREPLACE**. No overwrite/rename fallback or generic syscall interface.
   Fsync held parent, read back the exact inode/body, persist `published`.
6. Recheck all objects/inventories/authority, then persist batch `complete`.

Parent paths are canonical, no-follow and held; compare directory identity/custody
around effects. Fresh directory stages must be empty; published per-ID directories
must remain empty during maintenance. Base contents and own temporary names are
bounded and exact; unrelated `/etc` units are not removed. RAM16 GiB, root50 GiB,
`/mnt/stack`100 GiB, `/var/lib`1 GiB plus actual target staging filesystem1 GiB
free are required. No namespace/global process fallback or cleanup mechanism.
Native stdout bounded256 KiB, stderr discarded, deadline30 seconds, exact newly
created process group cancelled before leader reap on unsettled failure.

### Explicit resume outcomes

`apply` cannot resume pending work. `resume` requires the same private batch and
current authority. A `prepare-claimed` state without durable inode proof refuses
whether temp is present **or absent**; absence is not permission to create again.
`prepared` needs exactly its recorded staged inode and absent final path.
`publish-claimed` may find that exact inode at exactly one temp/final name; it
publishes the existing stage or reconciles the observed completed rename, never
recreates it. Both absent, both present, foreign inode or missing published state
refuse. Partial directories/files, source stages and failed publication evidence
remain; no repair/delete/reset/restart/adoption.

Provably published new ordinary rows can be observed before daemon reload: allow
NeedDaemonReload=yes/no, exact ordinary empty SourcePath and installed FragmentPath,
no drop-ins, inactive service/no PIDs/job/cgroup, only empty or exact reviewed
inactive socket relation while the pair is incomplete. Socket remains strictly
inactive with only its service relationship. These are *preparation* gates, not
activation or complete native validation; missing/extra properties fail closed.
Existing approved relays still use the stricter complete E3 gates. Native property
availability/relationship semantics require Parent's actual qualification.

## Handoff, reload and explicit evidence review

No daemon reload is performed. Success emits `state:needs-review-units`, actual
current `priorEvidenceSha256`, derived source filenames/hashes,
`daemonReloadRequired:true`, `activationPerformed:false`,
`installationCertified:false`. Parent separately qualifies/performs daemon reload
under the same stopped/interlock gates, preserving unrelated units (no restart,
enable, reset-failed or predecessor recovery). Then construct actual source v2
evidence and invoke [runtime-namespace.md](runtime-namespace.md) `review-units`
with the prior digest. That operation owns canonical no-container storage gates;
this SOURCE preparer provides **no Podman/store execution interface**. Only after
successful review and separate provider-ready verification may Parent activate.

After Parent legitimately changes namespace evidence, explicit `resume` of a
**complete** batch may update only its private evidence reference, requiring all
same namespace owner/stable IDs, exact owned source inodes, current approved relay
rows and stopped gates. It does not refresh the namespace marker. Pending batches
cannot launder a changed evidence binding. `status` is offline private-record
inspection only, never native/installed readiness.

## Volatile boot/rematerialization

No tmpfiles or RuntimeDirectory ownership normalization is used. Ordinary apply/
resume refuses a changed boot; missing published `/run` nodes are not repaired.
Explicit `rematerialize` requires a complete previous private batch, **actual new
boot** under the newly independently verified namespace pin, same stable namespace
identity/owner, current approved v2 evidence containing all exact owned relays,
unchanged persistent source inode/bytes, all old volatile targets and temps absent,
and closed/stopped full native gates. Existing directories, even correct-looking,
refuse rather than being adopted. There is no same-boot reset.

Persist a new directory epoch before effects, retaining up to8 prior boot/nonce/
directory claim records. Recreate only fresh absent exact `/run` directories using
the same claim/preparation/publication protocol. Persistent source files are not
rewritten. Interrupted new epochs use explicit same-boot resume; incomplete prior
claims cannot bootstrap a new epoch. More than8 epochs needs future reviewed
custody evolution, not automatic history deletion. This source protocol is **not**
a reboot or native-systemd certificate; filesystem stable-ID changes still refuse.

## Remaining Parent qualification

- Independently stage/hash/review this exact standalone source and all duplicated
  validation. No source test is Root/installed proof.
- Qualify real renameat2 NOREPLACE, fsync/CAS, held ancestors, fault/resume and actual
  new-boot materialization on disposable owned fixtures; no actual fixture executed
  by Worker. Native09 FD forwarding does not qualify this publisher.
- Verify ordinary native property sets, inactive relationships, default systemd
  directory owner/group behavior, source loading/reload and listener closure.
- Wire approved batch/evidence/interlock/handoff into Parent-owned lifecycle/CLI;
  preserve volume/context/model/render/Runner/catalog ownership.
- Qualify provider-ready, actual systemd FD activation, Rootful capless container
  forwarding and complete installed acceptance separately. Protected refusal cells
  remain stopped; no credential/provider/model/device continuation.

Source-only tests:

```text
python3 -I -m unittest discover -s tests_v2 -p test_host_relays.py -v
python3 -I -m unittest discover -s tests_v2 -p test_runtime_namespace.py -v
python3 -I -m unittest discover -s tests_v2 -p test_machine_credentials.py -v
```
