# Runtime public trust and mail leaf delegation

## Authority and scope

Standalone installation keeps the Caddy signing store root-private. Applications
receive only the root-owned `caddy_ca` public certificate bundle. Its declared
`rootlessAccess: read-only` policy grants no actor write/default-write permission.
Installer preparation validates certificate-only contents, removes historical
writable ACLs on these derived artifacts, and seals the private store without
changing key bytes. Exact execute-only ACLs cover the public volume's ancestry
inside the claimed scope, preserving authored masks and ancestors above it. No
system-wide trust, original cache, or unrelated application data is changed.

Mail is a narrower delegation, not a CA-store consumer. The publisher reads only
`mail.$DOMAIN` under the three known Caddy ACME/local issuer paths. It validates
certificate-only PEM material, not-before/expiry, exact SAN, non-CA leaf constraints, and
certificate/key public-key equality. It delegates exactly that certificate and
one unencrypted leaf key to `mail_tls`; never the CA key or another server's key.
No PEM bodies or OpenSSL/native-manager diagnostics appear in results/errors.

All entry modes require root and an absolute, immutable installed release path:
`--bundle /var/lib/<selected-state-root>/releases/<release-id>`. Passing a
`current` alias, relative path, traversal, arbitrary state root, or VM/venue
profile is not supported. The site manifest, domain metadata, scope ownership
marker and existing installer receipt remain authoritative. No alternate daemon,
installation journal, activation admission, or data ownership claim is created.

## Entry API

The existing installer calls remain:

```text
python3 <release>/ops/runtime-trust.py --bundle <release> --prepare
python3 <release>/ops/runtime-trust.py --bundle <release> --publish-mail
```

They inherit the installer's already-held `.install.lock` on shell fd 9.
`--installer-lock-fd N` selects another inherited descriptor for an internal
caller; it must identify that exact lock inode. Duplicating the shared open file
description avoids deadlock and preserves the parent's lock after helper exit.
Both operations require the selected journal/receipt to be exactly in `building`
with the normal phase history. Preparation runs before Caddy; publication waits
up to 120 seconds for issuance and does **not** reload or start mail. The installed
release must already be root-sealed. Existing installer invocations need no new
flags.

The external/periodic entry is:

```text
python3 <release>/ops/runtime-trust.py --bundle <release> --rotate-mail
python3 <release>/ops/runtime-trust.py --bundle <release> --rotate-mail --expected-intent <sha256>
```

External mode independently opens the **existing same** `.install.lock`, validates
root ownership, mode 0600 and single-link identity, and takes a nonblocking
exclusive flock for the complete operation. It never creates/replaces the lock.
Busy installers produce deferred metadata without reading credentials. The
optional expected digest is exact CAS for a manually reviewed invocation. A timer
normally omits it: after locking, the helper snapshots the active journal digest
and rechecks that CAS before publication, before reload and before acknowledgement.

Before publication, external mode requires:

- The installer-owned `current` pointer exactly names this immutable release.
- Root-owned, single-link, mode-0600 intent and receipt have identical bytes,
  schema 1, the known fields, `active` phase and complete ordered phase history.
- Every existing installer core/pinned input has its exact recorded SHA-256,
  including manifest and domain authority. An absent optional pin remains absent;
  historical three-file receipts do not authorize automatic rotation.
- Existing bundle/profile/hash verification, exact storage-scope marker and
  selected rootful/rootless actor identity all pass. Failed, retired, pending,
  unknown or mismatched journals refuse; no resume/phase change is attempted.
- The exact selected mail unit is loaded, active/running, free of queued jobs,
  has no drop-ins, outgoing reload propagation, success/failure activation hooks
  or pending daemon reload, and has the selected installed Quadlet bytes as its
  `SourcePath`. Rootless lookup selects only the manifest's
  exact domain UID/user/home/user manager; rootful lookup uses the system manager.
- The installed Quadlet matches the root-sealed release, is not linked or
  group/world-writable, and is owned by root or that exact rootless actor.

Rotation validates the existing public certificate bundle but does not publish a
new CA bundle or modify its permissions/parent ACLs. It does not poll for issuance;
missing mail issuance is deferred until a later tick. A stopped/failed/stopping
mail unit, pending job, or missing supported reload contract also defers before
reading/publishing the leaf. Unknown ownership/state is an error, not a success.

## Publication, retry and result semantics

Publication uses descriptor-relative, no-follow operations in the selected
root-owned `mail_tls` namespace. A bounded full preflight refuses unknown files,
incomplete/foreign generations, hardlinks, special files, writable artifacts and
noncanonical selectors before replacement or obsolete-generation deletion.
Certificate/key contents and ACLs are written/fsynced before the atomic selector
swap. ACL tools receive only explicitly inherited pinned descriptors; actor ACLs
are read-only and cannot write the delegated pair. Rootful mail receives no named
actor ACL and its key stays mode 0600.

The only intentional symlinks are the **existing installer-owned** absolute
`current` release selector and the publisher-owned relative
`mail_tls/current -> generations/<certificate-sha256>` selector. Neither is
followed as arbitrary path authority. Every traversed artifact/directory component
otherwise rejects symlinks; leaf files reject hardlinks. Obsolete derived
certificate generations are deleted, not retained as experiment backups.

After publication the helper rechecks CAS and activity and issues only:

```text
<selected manager> --no-ask-password --job-mode=fail reload webservices-mailserver.service
```

There is no start, restart, reload-or-restart, reset-failed, target activation,
manager-wide reload or trigger enable operation. `reload` cannot start a stopped
unit, and `--job-mode=fail` refuses to replace a concurrent stop job. A stop racing
publication therefore leaves the new pair unacknowledged and does not revive mail.

A root-owned `.reload-receipt.json` in `mail_tls` acknowledges only a successful
reload followed by active-unit, generation and selected-journal revalidation. It
contains schema, certificate generation hash, intent digest, selected UID and
selected Quadlet digest—no certificate/key bodies. It is **not** installation or
application acceptance authority. If publication succeeds but reload/acknowledgement
fails or is interrupted, a later authorized active tick retries reload even when
the pair is already published. Unknown/partial artifacts fail closed for exact
scoped review; the helper does not guess at cleanup or restore old data.

JSON results include `changed`, `deferred`, `reason`, `mailLeafPublished`,
`reloaded`, and `privateStoreShared: false`; authorized material operations also
return generation/intent digests. `changed` means this invocation changed the
published certificate generation, not that a TLS client observed it. Thus retry
can return `changed: false, reloaded: true`. Acknowledged unchanged generations
perform no publication, ACL mutation or reload.

Normal deferrals return exit 0 with `deferred: true` and an explicit reason:
`installer-busy`, `mailserver-not-selected`, `mailserver-not-active`,
`mailserver-job-pending`, `mail-reload-not-configured`, or `mail-leaf-not-issued`.
A failed/timed-out native reload returns `mail-reload-failed` with changed/deferred
metadata and **exit 1**, without acknowledging it. Validation/CAS/permission errors
exit nonzero with a generic diagnostic; no acceptance or automatic recovery is
implied. The Python `rotate_mail(bundle, expected='')` function requires its caller
to hold `installer_lock`; the CLI always does so.

## Required owning-stream integration (not installed by this helper)

The existing generator does not yet supply this API's reload contract. Its owning
stream must emit these two exact, sequential non-shell lines in the selected mail
Quadlet's `[Service]` section, for either placement:

```ini
ExecReload=/usr/bin/podman exec --user 0 mailserver postfix reload
ExecReload=/usr/bin/podman exec --user 0 mailserver dovecot reload
```

The ordinary standalone profile fixes `ContainerName=mailserver`. These commands
run as the **selected system/user manager actor**, not an arbitrary caller. The
owning mail image must prove both binaries/reload behavior and real certificate
uptake; source/mock tests do not prove that. Missing/different commands or native
`CanReload=no` produce `mail-reload-not-configured`, never a restart fallback.
Unknown venue/container namespaces are refused rather than guessed.

The installer/lifecycle owners must also:

1. Render root-owned `webservices-mail-leaf-rotation.service` (oneshot, root,
   `Restart=no`, `KillMode=mixed`, `TimeoutStopSec=45s`) and `.timer`, bound to the
   exact installed immutable release. During a native child operation, the helper
   defers TERM/INT until that bounded (20-second) child finishes, then aborts;
   do not release the installer lock while a direct child is still running.
   Use `--rotate-mail`, not `--publish-mail`, from a periodic/external trigger.
   Timer cadence is installer policy; avoid persistent catch-up/overlap. The
   helper's nonblocking installer lock is mandatory even with timer serialization.
2. Install/select these triggers only through the existing serialized installer;
   enable them only after the journal becomes `active`. Do **not** add Wants,
   Requires, ExecStartPre or other dependencies that can start mail or the stack.
   Ordering-only dependencies are not activation authority. A timer tick when
   mail is stopped must remain deferred.
3. Extend failure, interruption, quarantine, retirement, upgrade deselection and
   trigger-stop paths to disable/stop the exact selected rotation timer **and**
   stop/wait for its oneshot service, alongside the existing update trigger.
   Acquire/retain the same installer lock. A running external helper finishes or
   exits before that lock can be taken; disable the timer while holding it before
   changing selection. A native reload timeout/interruption can leave a selected
   manager job after its client exits: cancel/wait for that exact mail reload job
   (and stop the selected mail unit on failure) before proceeding. Never cancel
   unrelated jobs, acquire a second lock as a substitute, or allow a failed
   selected journal to be revived. Verify both triggers stopped/disabled with no
   remaining selected jobs. No such journal/installer edits are owned here.
4. Exercise real rootful and rootless rotation, concurrent installer/stop races,
   reload failure/interruption, native ACL denial, and post-reload TLS uptake.
   These remain installed/deployed proof dependencies, not accepted delivery cells.

## Scoped tests and limits

Run `python3 -B scripts/test-runtime-trust.py` (bounded externally to 120 seconds).
Nonroot tests cover mocked active selection/receipt/hash/CAS, exact actor/unit
selection, stopped/failed/job/unsupported deferral, retry/acknowledgement,
interruption and CLI/lock behavior. Disposable temp-root filesystem tests spoof
only ownership metadata for source coverage; they exercise links, hardlinks,
FIFOs, permissions, namespace refusal, descriptor publication/ACL argv and atomic
hash-only receipts. Real **local** OpenSSL tests use synthetic temporary leaf/CA
material; no network or installed app calls occur.

Seven separate root-only ACL/actor-denial fixtures are skipped as nonroot. Do not
use sudo to run them under a source-only delegation. Neither the mocked ownership
checks nor skipped fixtures establish native security, mail delivery, timer,
recovery or application acceptance. No complete host acceptance is claimed.

JupyterHub and spawned notebooks still mount only the public bundle at `/ca`, with
normal Python/Requests/Curl verification directed to combined system/site trust.
Images remain site-independent; the host path is a runtime input, not baked trust
or a TLS-verification bypass.
