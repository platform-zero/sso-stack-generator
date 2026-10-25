# Standalone host deployment contract

A site manifest may explicitly select `"deploymentMode": "standalone"` for the
ordinary native Podman/systemd application stack. This is not an activation skip
flag. The mode is part of the hashed site manifest and generated bundle metadata.
Omitting the field preserves the existing managed-site contract, including its
Latium agent-VM validation and control-checkout requirement. Unknown modes fail.

Standalone manifests also declare, for example:

```json
"installerStateRoot": "/var/lib/stack-example",
"storageScope": {"root": "/mnt/stack/example-stack", "dataClass": "production"}
```

`installerStateRoot` must match `podman.rootful_state_root` in site configuration.
It binds generated rootful mount/environment paths as well as journal selection;
a runtime environment override may not relocate only half of that authority.
The default remains `/var/lib/webservices`; dedicated standalone metadata roots
use `/var/lib/stack-*` and may not overlap application storage. Failed-selection
quarantine skips an unconfigured unit only after native `not-found`, inactive,
empty-fragment/unit-file-state evidence; unknown/active units still refuse it.

Use `synthetic` only for deliberately disposable fixture data. All private domain
state/image/volume roots and named application data stay inside this canonical
scope. The installer claims only an empty directory tree, never nonempty unclaimed
data or retained service accounts. A root-owned, atomically published ownership
marker binds the site, identities and private roots for subsequent operations.
Existing marker identity/path drift is refused; there is no broad adoption flag.

Execute-only per-domain ACLs cover selected state, graph and volume ancestry,
never an operator's private home or another parent above the scope. Authored ACLs
and their masks are preserved rather than unmasked by `setfacl`. Private leaves
remain mode 0700. Standalone preparation does not chmod/re-own the legacy shared
Podman cache parent. CI SSH setup uses its actual IR domain and can claim only a
new/empty fixture directory, not foreign existing keys or a linked path.
Standalone private volumes are initialized through no-follow directory FDs; there
is no legacy-store copy or recursive ownership migration on repeated installs.
Actual allocated subordinate-ID ranges populate the subsequent runtime table,
including when the site lets the installer select an unused range.

Preparation errors/signals are journalled before account/volume/unit work, not
only after unit selection. A copied immutable stage is immediately root-sealed
and standalone stages remain root-private. New receipts also bind encrypted
settings and base-image pin bytes; historical receipt pin sets remain readable.

For an explicitly synthetic, **never-selected initial** preparation only, the
journal supports exact-CAS `--seal-unselected SHA --reviewed-data-state` repair of
the old archive-copy ownership reset, then native
`--retire-unselected-intent SHA --reviewed-data-state`. Seal checks the entire
new derived tree for foreign owners, links and special files before changing any
owner. Retirement requires bound storage, no current/previous pointer, no installed
stack configuration, inactive selected units, absent/disabled boot triggers and
no stack jobs. This does not stop/restart services, erase data or authorize a
production upgrade. Ordinary selected-failure quarantine remains separate.

The storage marker is not a backup, a production-data recovery approval or an
application/recovery acceptance result. Those lifecycle gates remain separate.

The existing journal `--complete-clean-reset --expected CURRENT_INTENT_SHA`
operation (under the canonical inherited FD9 lock) can freshly review an already
`retired-clean` selected synthetic installation after an unselected preparation
has left new synthetic data. Eligibility additionally authenticates the exact
prior private completion result and intent/plan bytes, their source/release/scope
binding, hashes and zero-acceptance/no-restart flags. That history grants **no**
new stopped lease or permission to replay its inventory. The backend still obtains
new actual runtime custody, offline/trigger/job/account/mount checks, a full
current inode/hash/CAS inventory and a new same-process stopped lease before any
deletion. Missing/tampered history, changed source or new unsafe state refuses.
Prior durable attempt evidence remains retained; neither a previous clean label
nor a fixture counts as a clean host run.

For engineering iteration with a non-cold shared default store, the separate
[owned synthetic data-only reset](native-owned-synthetic-data-reset.md) preserves
that store completely. It requires its own fresh scoped inventory/CAS/stopped
lease and records `completeCleanReset=false`; it must not replace the full reset
or supply cold-store/acceptance credit.

Native Seafile preparation can leave UID-mapped **read-only image-cache clones**
in the default Root store. The reset inventory never chowns or prunes them. Its
metadata-only classification requires a receipted registry config ID for the
three native support images, an image-index `mapped-layers` reference, the same
parent and compressed/uncompressed diff identity as the indexed original layer,
and exact declared apps/platform UID/GID maps and private directory custody.
Unindexed, writable, changed-payload or foreign-namespace directories still
refuse. These retained immutable-cache observations grant no execution authority,
application acceptance or cold-store credit; the normal zero-container/volume/
Buildah and all other custody checks remain mandatory. No layer contents are
opened or walked by this classification. A non-cold default Root store refuses
complete reset: matching an image config ID is **not** ownership/deletion
authority over shared cache bytes. The default-store dispatcher permits only
exact unforced source-selected network removal, never image deletion or prune.

Authenticated prior completion evidence may supply the original inspected
network-to-bridge identity when its definition was already removed. That
provenance is retained across new reset reports, bound to unchanged source,
release and protected result/intent hashes. Current kernel link/address/route
absence must still be freshly observed; no prior clean label, inventory or
lease is replayed and no manual kernel cleanup is authorized.

For a retired-clean selection, the exact source-declared rootful Caddy
`volumes/_logs/caddy:/var/log/caddy` mount also identifies its three **empty**
Root-owned/operator-group namespace parents. Their full mode, access/default
ACL, child membership and link count must match the closed private profile.
This is neither a fixture nor a rule for adopting populated log data: any new
child, changed ACL/owner or different source mount refuses without repair.
Operator build caches are not application scope; keep the session-isolated
Gradle cache outside the native reset scope, never classify it as service data.

A standalone site:

- uses the ordinary `webservices` unit namespace, not the isolated venue profile;
- does not declare an `agentVmSpec` or manage a control checkout;
- does not emit maintenance/software lane-workspace metadata;
- omits the Caddy managed-control socket bind and the explicitly marked Caddy
  control/agent-API route block (ordinary application routes remain selected);
- does not classify controller/VM proof as part of application delivery or defer
  selected notebook/runner workflows merely because of the historical controller;
- bounds generated build services to 30 minutes, two CPUs, 8 GiB and 512 tasks,
  using selected private build scratch rather than unrestricted host `/var/tmp`;
- binds collector journal ingestion to its fixed domain UIDs plus root, requires
  current collector scope hooks, and derives the unit-namespace filter from site
  policy. Existing finance/private-database exclusions still apply;
- allocates ingress/security log storage under the declared volume root and
  refuses retained host log mounts; requires access and error URI-redaction hooks
  rather than letting callback/query credentials enter logs;
- remains subject to the existing source, image, domain, resource and native
  installer safety checks. It is not permission to operate unrelated accounts,
  storage, services or sockets.

The native role verifier requires agreement among the manifest, bundle and domain
metadata, their core provenance/hash bindings, absence of managed-role artifacts,
and absence of the managed control socket in the IR mounts. A venue cannot simply
be relabelled standalone. Passing this structural contract is not application,
shared-login, persistence or recovery acceptance.

The generator refuses an unrecognized control-mount shape or ambiguous Caddy
source block rather than guessing how to strip it. Input materialization changes
happen in the newly generated artifact from owning source; do not patch installed
Caddy output manually.

## Native Seafile ownership preparation

The bundled installer invokes internal journal preparation **before** any domain
runtime projection. This is not a public permit-emitter or a replacement install
command. Exact preparing dual records, FD9, immutable inputs, storage marker,
offline actors, public-slot custody and an explicit enabled realm-owner subject
bind the operation. Caller-provided authorization files/hashes and replayed or
already-projected preparation are refused.

Main uses its own protocol validator; it never imports service Python as Host
Root. The owning module independently validates the same authorization in its
mapped native namespace. Temporary initialization uses the selected immutable
images, eventual actor UID/GID maps, a networkless private loopback namespace,
a finite unprivileged relay and a fixed read-only public hosts file. No host
listeners or actor managers are activated. Executable configuration is staged in
the private release worktree, not noexec `/run`; one-shot credentials stay in a
private temporary capsule and never become normal service environment values.

An upstream byte-contract check precedes data creation. Native exit zero,
account/CAS proof, a separate read-only native verification, bounded clean stops
and final source/custody rechecks must all succeed before Main publishes the
normal hash-pinned authorization and derived environment. A log proof alone
confers no admission. Failures consume preparation and preserve data/evidence;
there is no adoption, retry repair, data deletion or predecessor restart.

The current executor is fresh-only and deliberately refuses an existing
predecessor until its canonical owned-state carry-forward/recovery lifecycle is
implemented and qualified. Source tests and public namespace probes are not
installed bootstrap, application, upgrade or recovery acceptance.

Native preparation honors source-declared numeric container UID/GID within the
exact declared maps, just as the eventual service does. In particular the pinned
MariaDB mysql identity must not silently become namespace-root during preparation.
On failure, a private `native-seafile/failure-observations.json` retains only own
CID, running boolean, bounded exit code and OOM boolean (or observation unavailable).
Stop cleanup does not overwrite that failure record. A database probe can expose
only predefined readiness/authentication/missing-database/connectivity/native-exec/other
classes, never raw client diagnostics or arbitrary SQL error codes. Only exact own-CID
MariaDB probes can capture stderr privately for classification; it is bounded with
stdout, never printed or persisted, and all other commands still discard stderr.
Database initialization has a finite 180-second startup budget (the service's
60-second start period is not its entire startup budget). After its deadline,
one exact-own-CID socket probe may emit a predefined initialization observation.
An available initialization socket never substitutes for the required TCP service
account/database readiness gate. An attached own-CID start can drain the private
MariaDB console in memory into a closed set of startup/permission/resource codes.
No raw console file, inherited output, line text, SQL, service source or secret is
retained. The reader has bounded chunks/tail and an 8 MiB classification ceiling;
helper signals do not proxy to the database. A helper that cannot finish cleanly
cannot produce a successful temporary-stop proof. Failure observations may also
classify a bounded set of process roles, scheduler states and kernel wait classes
from the exact nonempty own-CID cgroup. A held PID descriptor, unchanged main PID,
process start identity and cgroup membership are rechecked. No PID, arbitrary
process name, argv/environment, kernel symbol or raw `/proc` content is emitted.
Empty/foreign/global/unavailable cgroups have no global process fallback. No exception text,
environment, service source, child log, or secret is a diagnostic field. The database's
isolated network gets a deterministic source-derived hostname with a local readonly
hosts binding, so bootstrap never needs external DNS for its own hostname. Namespace
peers have separate hosts files and do not request forbidden Podman hostname flags.

## Native stopped backup and restore

This is a bounded **synthetic, cold, same-machine, same-release and exact-receipt**
recovery contract, not production/database-consistency or installed acceptance.
It never stops/starts a manager, enables a trigger, restores Run, or prunes data.
Stop through the canonical lifecycle first. Every selected manager must be
cleanly inactive, selected units/APIs/triggers closed, NSS/subids/source/unit
custody intact, and own/mapped processes and writable FDs/shared mappings absent.
Physical reserves remain memory16GiB, root50GiB and stack100GiB, plus staging.

Obtain current native selection pins without minting an operation permit:

```sh
stackctl backup --state-root /var/lib/webservices --plan --json
```

Pass `selectedRelease`, `intentSha256`, `receiptSha256` and `planSha256` explicitly
as `--expected-release`, `--expected-intent-sha256`,
`--expected-receipt-sha256` and `--expected-plan-sha256` respectively:

```sh
stackctl backup --state-root /var/lib/webservices <exact expected source hashes> \
  --archive /root/stack-backups/snapshot.age --recipient age1...
stackctl restore --state-root /var/lib/webservices <fresh exact expected source hashes> \
  --archive /root/stack-backups/snapshot.age --archive-sha256 <ciphertext SHA256> \
  --identity-file /root/separate-recovery-identity/identity.txt
```

Use pre-existing root-private directories outside both stack data and native
metadata. Retain the identity separately from the archive directory. The only
crypto backend is the root-trusted `/usr/bin/age`, executed by its held FD; there
is no operator-home fallback or configurable executable. No private key or proof
JSON is accepted on the command line. Identity material is passed by held FD.

The public controller retains the existing canonical flock's actual open file
description as FD9. The journal producer records `recoveryCustody` identically in
both current Root records, without changing phase, steps or existing proofs.
That record is source/directory custody, **not a persisted operation permit**.
Execution additionally requires a fresh process-local, source-bound, expiring,
one-use stopped lease for the exact destination/recipient or archive/key hashes.
An unchanged existing custody record is reused, never rebased on drift. Refresh
selection pins after the first publication. Any later receipt/source change
makes that exact-receipt archive incompatible; it is not a migration format.

Every selected IR mount is classified. Named persistent data and supported exact
bind leaves are included; `%t/podman/podman.sock` and the exact selected actor
socket are transport, not archive data. CI `forgejo-runner-ssh` / explicitly
source-declared CI `dataRoot`, test result leaves, and Caddy logs/public trust
have exact owning classifications. Whole state, graph/cache, home/auth stores,
unclassified binds, cross-domain mounts and overlapping roots refuse explicitly.
Canonical runtime/configuration is archived as checked **reference material**;
native restore never replaces those immutable source/unit/projection inodes.
Only selected mutable data roots are swapped, with originals retained and no
restart. Actor `.config` must match the exact selected unit/account-config
namespace; unknown files are refused before content is opened.

Payload ACLs/xattrs, hardlinks, symlinks, special files, set-id metadata and mount
boundaries are currently unsupported and **refused**, never silently omitted.
Canonical ancestry ACL/defaults use the existing native source policy and are
not changed. Only a newly-created empty Root-owned staging inode is sealed0700;
existing data/source directories are never recursively repaired. Stable payload
UID/GID/mode/mtime/bytes are checked; original displaced inodes remain retained.
The authenticated plaintext tar is bounded by the existing four-GiB payload
limit plus manifest/tar overhead and held in a sealed memfd, never a filesystem
spool. Restore budgets the encrypted input size before allocation and checks
available physical memory before each plaintext chunk, retaining at least16GiB
available RAM. Larger backups or insufficient restore capacity refuse rather
than omit payload or cross the host reserve. These are source/runtime limits,
not proof of a populated installed recovery pass.

Wrong keys, tamper, source/CAS/lease loss and incomplete swaps do not authorize
restart. Preserve the protected `.host-recovery` journal, stages and originals;
there is no automatic public recovery/pruning or original-data adoption. The
historical synthetic `host-recovery.py` controller API remains separate and its
mock-crypto tests are not proof of installed or real consistent restoration.
