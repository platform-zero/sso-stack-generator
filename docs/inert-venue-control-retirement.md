# Inert venue control retirement (operator-only)

This is a narrow host-administration interface for an already retired, never
activated venue. It is **not** a normal deployment command, an automatic build
step, a general host purge, or permission to stop unrelated production services.
The helpers belong under `ops/host-admin/`; they must not be added to generated
service units or invoked automatically by the deploy UX.

## Authority and source layout

The owning sources expose these Python APIs:

- `policy_fence.fence_host_transport_policies(bundle, selector, ledger,
  reviewed_sha, provenance_sha)`;
- `inert_control_lease_native.retire_inert_control_lease(bundle, selector,
  ledger, reviewed_sha, provenance_sha, plan_sha)`.

A source checkout is not a native-ready execution package. An authorized operator
must assemble a new complete protected runtime cohort from reviewed committed
sources, an exact public executable-source map, and private per-target inputs.
Do not patch the original generated target or its provenance, substitute another
candidate's ledger, create a shadow target, or execute the target's historical
scripts as the newly reviewed implementation.

The native lease's flat runtime source closure and sibling `SOURCE-LOCK.json`
are deliberately distinct from this repository's owning source layout. A public
source template has no configured real target. Missing configuration must refuse;
complete synthetic fixtures exercise the implementation without authorizing a
real operation. Never commit an actual configured runtime lock, target artifact
inventory, installed slot, host-role sidecar, plan, ledger, private receipt or
native invocation record to this repository.

The committed public target-ops subset is not necessarily the complete original
artifact. Authenticate the entire generated artifact map, including exactly the
known generated inputs, from protected original historical source proof. Bind its
bytes and modes separately from the public committed subset. Unknown or omitted
members must refuse. Historical generated worklane files are input data only;
this interface neither executes them nor implements future worklane behavior.
A configured receipt hash or a test Boolean is not independent proof of origin.

## Preconditions

An authorized protected caller must establish actual initial-root authority:
effective UID **and GID**, full UID/GID maps, self/PID1 user/PID/mount namespaces,
actual kernel/context/receipt bindings, and current held source/input identities.
Use isolated Python without site loading or bytecode writes (`-I -S -B`). Reject
symlinks, code caches and alternate cache prefixes. Close the complete executable,
transitive registry and external host-slot source/manifest closure before dynamic
privileged loading. Test fixtures and peer assertions cannot supply this authority.

Authenticate the original plan and complete retirement history, including typed
saved-plan equality, the full policy-fence record, the actual source-context
closure and all distinct publication epochs. Do not coerce Boolean/integer/float
aliases, normalize malformed history, discard a completed pending-image retirement
record, or accept a smaller illustrative record in place of the actual wire.
Verify absence of all owned retired host units, managers, jobs, processes, graphs,
accounts and paths as required by the selected API. Preserve all failed evidence.

A completed boot tmpfiles oneshot need not be stopped. Its exact successful
active/exited, Type=oneshot, RemainAfterExit=yes state is quiescent only with both
MainPID and ControlPID zero, successful result/status, absent cgroup, no queued
job and no private writer/controller process. Active/exited alone is insufficient.
Never extend this exception to ordinary host units or user managers, and do not
stop or reset global boot services to make a precondition pass.

## Input bounds and time budgets

Keep executable CODE admission separate from nonexecuted DATA admission. The
bounded DATA reader includes empty files and large artifacts, hashes every byte,
and includes every member: no node_modules exclusion, filtered tree or omitted
empty file. DATA bounds are 32,768 nonroot entries, 64 MiB per file, 512 MiB total
and 60 seconds per complete scan. Streaming chunks are at most 65,536 bytes.
These broader limits apply to the nonexecuted generated-DATA reader, not every
input reader. The native lease's original-ops reader still requires nonempty
members of at most 2 MiB; authenticate that the actual original artifact satisfies
that narrower contract rather than inferring acceptance from a larger build test.
Preserve full named/held identity, ownership/mode, hardlink, cache, symlink,
directory-membership and final metadata/hash checks. Do not retain one descriptor
per DATA member or raise descriptor limits to mask a reader defect.

The policy callable's operation budget is 90 seconds; the native lease callable's
is 120 seconds. Preserve each reviewed deadline origin: setup before an epoch is
not newly claimed covered by that epoch; finite external scheduling also bounds
the invocation. A reader's independent 60-second budget does not imply multiple
reads fit the remaining operation budget. Recheck after expensive observations
and immediately before destructive calls, publications and successful completion.
An in-flight syscall cannot be retroactively undone. Measure the complete actual
bounded read-only path before a native mutation; source timing and fake clocks
are not native timing proof. Do not increase caps to conceal a late-boundary gap.

Use finite external scheduling bounds, including memory/CPU limits, Restart=no,
UMask0077, core dumps disabled, and start/runtime/stop timeouts. Enforce the actual
host's storage/memory reserve and production-data safety requirements separately.

## Mutation and continuation

Retire the exact sudoers policy first, then its exact tmpfiles policy, while
retaining the original readonly, no-follow, close-on-exec, noninheritable policy
FDs through both deletions, parent fsyncs and all fence journal publications.
Authenticate actual policy absence and the complete published fence before
retiring the existing lifecycle lease and its exact empty runtime directory.
Never create a missing runtime or lease merely to retire it.

Every mutation requires a durable owned issued epoch and current held CAS/input
checks. An uncertain issued-present state must refuse; it does not authorize a
second delete. Continuation is limited to exactly owned absence and the original
saved identities/history. Do not rewrite an old operation hash, clear a pending
marker, reset failed units, discard red evidence, or blindly retry after a timeout.

POSIX unlink/rmdir are **not inode-CAS**. Held FDs, flock, proc snapshots and
repeated checks do not freeze Root writers or forks. Explicit exclusive or
cooperative operator exclusion of **all relevant Root writers** is indispensable,
including source, ledger, parent, mount, policy, lease, controller and job writers.
Stop the affected operation on a concrete safety failure; continue independent
safe engineering rather than weakening the failed gate.

Source-test passes, policy retirement, lease absence and source-image preparation
are scoped proofs only. They do not establish installed application functionality,
recovery/restore, a complete Podman purge, namespace release or repeated-install
acceptance. Transport, configuration, provisioner and installed-source disposition
need their own genuine creation/ownership evidence. Retain selected source/context
until every dependent continuation can safely complete.

## Ordinary-user regression tests

See [portable SOURCE regressions](inert-control-source-tests.md) for the complete
native and policy groups, their two required explicit external public datasets,
license/nonvendoring boundary, isolated execution and synthetic-only scope.
Private profiles, result/audit directories and real historical evidence are never
release inputs. Test parameters do not add production authority parameters.
