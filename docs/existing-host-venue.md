# Existing-host isolated integration venue

## Boundary

The venue prepares the selected composition beside protected host state using
separate account/subid identities, rootful and rootless Podman graphs, native
unit names, bind roots, sockets, listener mappings and a distinct guest identity.
A valid selector is **not** permission to activate a legacy deployment.

Never run `install-podman-bundle.sh --activate` against a venue: its explicit
venue refusal remains intentional. Do not patch generated bundles, replace a
shared graph, issue a global prune, change protected bind contents, or relax a
listener/capacity gate to get an installation attempt.

## Exact diagnostic-cache retirement

Even a Podman image inspection by a short name may create a zero-byte alias lock
in the selected account home. After the experimental graphs/managers are fully
retired, `venue-shortname-cache-retire.py --selection vaultwarden-inspect
--expected-ledger-sha SHA256` accepts only the declared Vaultwarden image's
verified registry receipt and a completed exact owned reset. It journals only
that account's empty lock and two private parent inodes; authored bytes, other
children, wrong ownership, changed CAS, live processes or unknown mount namespaces
refuse before deletion. No Podman command is run against a cleared graph.
The historical build-base mode remains separately scoped to its two accounts.
Neither mode removes application data or grants activation.

## Supported lifecycle today

| Operation | Versioned implementation | What it proves |
| --- | --- | --- |
| Inspect proposed isolation | `ops/verify-existing-host-venue.py` | Read-only selector/rendered-resource checks; never activation authority |
| Inspect past known listener refusals | `ops/inspect-existing-host-venue-beyond-listeners.py` | Static classification only, not a bypass of the normal preflight |
| Prepare inactive release | `ops/venue-install-inert.py --prepare-inactive` | One protected journal coordinating exclusive accounts, private release/env files, managers, actual binds, ACLs, volumes and inactive units |
| Prepare immutable image inputs | `ops/venue-registry-images.py`, `ops/venue-build-base-images.py` | Exact selected image/store IDs and frozen base identities, not running services |
| Discover local build outputs | `ops/venue-local-build-images.py` | Bounded selected builds and output/intermediate receipts; not frozen release inputs |
| Retire inactive release | `ops/venue-install-inert.py --retire-inactive` | Guarded reverse-order retirement of the exact inactive installation, not populated-data reset |
| Prepare required runtime bridge | `ops/render-existing-host-guest-network.py --prepare-owned --journal ...` | Applies only the exact new guest fence before atomic network creation; journals UUID and persists only its own native XML; no guest or autostart |
| Stage owned native boot fence | `ops/render-existing-host-guest-network.py --stage-owned-boot-fence --journal ... --expected-journal-sha SHA256` | Preactivation/never-guest context, idle units, exact live XML/fence CAS; installs one root-owned immutable network-specific libvirt hook; no daemon restart or autostart |
| Prove native boot fence before autostart | `ops/render-existing-host-guest-network.py --prove-owned-boot-fence --journal ... --expected-journal-sha SHA256` | Requires active libvirtd, all domains stopped with autostart disabled, no stopped autostart networks and no attached interfaces; refreshes daemon, cycles only the owned bridge with fence retained, requires fresh native hook proof before enabling only its network autostart; no host reboot or VM start |
| Prepare two synthetic media inputs | `ops/venue-bind-dirs.py --prepare-fixtures` | Exact Jellyfin readonly/qBittorrent writable selected fixture bindings; creates only two absent owned leaves and two new parents, records original inodes/UIDs/modes; no media/data import or service start |
| Repair missing selected media inputs after failure | `ops/venue-bind-dirs.py --repair-failed-fixtures LEDGER_SHA256` | Exact failed-consumer/current-boot quarantine, ledger CAS and lifecycle lease; refuses any existing path rather than adopting it; source/epoch-bound specific repair, not automatic restart |
| Repair a missing owned log bind | `ops/venue-bind-dirs.py --repair-failed-logs ...` | Only after completed selected failed-start quarantine; creates absent immediate rootful log children under exact receipted parent, never adopts or resets data |
| Clean exact stopped native bootstrap metadata | `ops/venue-start-quarantine.py --cleanup-stopped-native SHA256 ...` | Under the same fenced lease/failed-ledger CAS and specific repair; journals exact source/image/unit/epoch-owned exited IDs before non-force cleanup/rm; no volumes or data reset |
| Review a proven stale prior-result observation | `ops/venue-start-quarantine.py --review-stale-result-unit UNIT --reviewed-ledger-sha SHA256 ...` | One selected owner/unit, failed result whose activation/exec timestamps precede this attempt, changed lifecycle source, fenced current-boot context; no start or data reset |
| Review changed-input recovery | `ops/venue-install-inert.py --retry-reviewed-failed-sha SHA256 ...` | Explicit failed-ledger CAS, current-boot fenced context and one unconsumed specific repair; retained source/epoch-bound native object IDs checked, not a new clean installation |
| Reset exact experimental owned contents | `ops/venue-install-inert.py --reset-experimental-owned-sha SHA256 ...` | Completed quarantine/current-boot fence, no guest, no containers/pods/foreign objects, all original source/parent/data inodes and process mount namespaces checked; journaled native-network IDs and fd-relative data deletion; no backups or starts |
| Retire only the never-guest owned bridge | `ops/render-existing-host-guest-network.py --retire-owned --journal ... --expected-journal-sha SHA256` | Idle namespace/fenced authority, exact UUID/native XML/fence bytes, no attached kernel interfaces or referencing domain; destroy/undefine precede deletion of only its own nft table |
| Retire the three inactive installed isolated control units | `ops/venue-start-quarantine.py --retire-host-role-units RETIRING_LEDGER_SHA256` | Exact native graphs/194 units/env retired first, false quarantined immutable context, three unchanged source-manifest-bound files, no jobs/activation/enablement/drop-ins; inode/CAS journal and daemon-reload only, original manager empty-unit gate unchanged |
| Retire only Homepage-created runtime config logs | `ops/venue-domain-runtime-inert.py --retire-reviewed-runtime-logs LEDGER_SHA256` | Reset/stopped managers, canonical source mount, all seven original trees/pointers unchanged except two new owned log paths, no UID writers or namespace mounts; exact hash/inode intent, no backup or service start |
| Remove only a retired false runtime capability | `ops/venue-start-quarantine.py --retire-runtime-authority RETIRED_LEDGER_SHA256` | Full exact owned retirement, all old paths and account names/UIDs absent, same selected immutable context, false quarantined receipt; journaled unlink under lifecycle lease, no runtime grant or legacy fallback |
| Retire only the old empty control runtime directory | `ops/venue-start-quarantine.py --retire-runtime-directory RETIRED_LEDGER_SHA256` | Fully retired old scope/accounts/paths and false capability, selected old context, only its root0600 empty lifecycle lock remains; exact directory inode intent, held lease, no recreation/adoption or authored-state deletion |
| Attempt isolated activation | `ops/venue-install-inert.py --activate-isolated` | Explicitly upgrades a fresh frozen-input preparation to a current-boot version-2 intent; native startup is not integrated acceptance |
| Quarantine selected activation | `ops/venue-install-inert.py --quarantine-start` | Fences runtime authority, cancels selected late jobs and stops exact native units/sockets while retaining data; never retries |

Inactive preparation remains version 1 and grants no activation. Explicit
version-2 activation requires the selected immutable host context, matching
bundle/site provenance, every registry/import store ID, frozen producer aliases,
61 exact empty owned binds, idle units/jobs, free listeners and physical reserves.
Only source-declared API consumers start their separate rootless Podman sockets;
manager environment and resulting socket identities are checked first. Intent
precedes readiness/authority and every queue acknowledgement. Authority writing,
controller mutations and quarantine share the same private lifecycle lock.
Readiness observes actual startup leaves, not merely successful Wants targets.
A failed start is fenced and stopped without deleting data or automatic retry.

Declared health probes are translated into native Podman health argv, preserving
exec-form argument boundaries and shell-form container-dollar escaping. Only
referenced deployment inputs enter the existing private per-service environment;
public Quadlets/argv contain aliases, never their sealed values. Exec-form probes
with deployment-variable interpolation refuse until a rendered-argv contract is
available; the selected composition uses literal exec probes. A daemon referenced
by a `healthy` dependency must have an enabled probe and uses Podman's native
`--sdnotify=healthy`, so its ordered consumers cannot start merely because conmon
started. Podman 5.4 requires this flag through `PodmanArgs` (after the generated
conmon default), not the boolean-only Quadlet `Notify=` key. Startup remains
bounded by the service timeout and installer quarantine. Native parser/argv and
translator tests are source proof, not deployed application-health acceptance.
Native version-2 retirement invokes the existing exact host-unit retirement
helper after graph/unit/env disposal and before manager retirement. A foreign or
changed host unit stops this sequence; the manager empty-unit gate is unchanged.

Bridge publishers require the actual selected gateway to exist. Runtime bridge
preparation deliberately leaves network autostart **off** until durable fence/boot
ordering is installed; it is not guest boot readiness. The two explicit boot-fence
operations install and natively exercise a synchronous libvirt `start/begin` hook
before enabling only this network's autostart. The hook is a self-contained,
root-owned immutable executable with an embedded policy: exact network UUID and
semantic XML, source fence bytes and native nft rule fingerprint (excluding only
kernel handles/version metadata). It never calls libvirt, flushes tables, replaces
foreign rules, starts a VM or grants application runtime authority. Other network
names and stop events pass through unchanged. A fresh current-boot receipt proves
libvirt invoked the hook before the bridge start; it is NOT a host cold-boot test,
guest lifecycle acceptance or a reason to enable VM autostart. Exact never-guest
network retirement removes only its unchanged receipted hook/proof after network
undefinition and before its own fence table deletion. Existing network names,
routes, interfaces, fence tables or journals are never adopted or retried.

The two media fixtures are separate from the 61 data binds. Initial inert
preparation materializes their actual source paths; activation requires the
original receipted nodes, not just an accepted static substitution. Empty source
directories are not playback/download functionality proof. Populated experimental
reset includes only those original fixture leaf inodes, restoring recorded modes;
empty retirement removes only their four unchanged, empty nodes before the
original stage parents. Existing/authored fixture paths are never adopted or
recursively removed by preparation/empty retirement.

The private release builder must reapply `podman-loopback-endpoints.json` after
SOPS/template rendering and BEFORE its immutable manifest/current pointer is
published. Otherwise raw `stack.config` templates silently restore names such as
`postgres:5432` that do not resolve across separate rootless stores. The existing
installer's `--rewrite-rendered-configs` build-only mode shares its normal routing
pass and refuses activation/inspection/installation options. The inert builder
records that pass's source hash. Use only on a new unpublished copy; an installed
immutable release is never patched to recover this producer defect.

Cross-domain ACL namespace inspection fails closed on unreadable/invalid procfs
mountinfo, including permission denial; it never interprets an unknown namespace
as unmounted. Only a disappeared process is skipped. POSIX ACL metadata fixtures
isolate that separately tested mount screen rather than treating a transient
whole-host procfs error as proof of the intended ACL rejection.

Readiness checks correlate both native activation and exec timestamps to the
current start epoch. A prior attempt's retained failed Result is pending, never
success and never a new failure; current-epoch failures still refuse immediately.
No reset-failed or automatic retry hides previous evidence. Proven retained network
IDs survive later systemd GC via their existing root receipt; new objects still
require source/owner/unit/epoch proof, and an ID substitution refuses. Each new
intent records the lifecycle code hash; an old legacy receipt without that hash
is explicitly labelled rather than falsely upgraded. Failure/fence evidence is
written under the lifecycle lease after authority is fenced, before native stop.

Version-one preparation includes actual rootful log-bind children, separate from
the 61 data binds. Failed-start recovery never relaxes the fresh-stage gate: it is
a separate explicit ledger-CAS operation. It checks exact retained stopped native
bootstrap IDs/image IDs/unit labels/epoch and network IDs/source/unit creation
proof (durable UID-bound journal if systemd GC erased oneshot timestamps), rejects
live or foreign objects, preserves populated bind inodes and old attempt evidence,
and consumes only the repair tied to that previous start epoch. Retained bootstrap
containers must first pass the separate exact-ID cleanup operation; starting with
leftover containers is refused. The old proof and cleanup intent/result remain in
the ledger. Existing stopped
selected API socket nodes are checked against inactive selected socket/service
units; generated units and mounted configuration inodes are never patched.

Experimental populated reset is separate from inert retirement and startup. It
keeps the original top bind/log/volume inodes, removes only their contents without
following symlinks or crossing filesystems, restores reviewed top-level ownership
and ACLs, removes only receipted native network IDs and the exact readiness marker,
and preserves version-2 attempts/failure evidence. Empty-state proof allows reverse
retirement without pretending the stage was never activated. Frozen retirement
uses the complete selected direct/local identity map and bounded catalogue, not a
legacy one-archive/direct-only assumption. Stopped metadata cleanup needs a fenced
exact epoch/CAS, not an unconsumed restart repair; it never grants runtime authority.
A guest must be separately exactly retired first. No global prune/data backup.
If a host reboot interrupts completed reverse retirement, only the two exact
source-selected `/run` roots may be classified boot-lost: `/run` must be tmpfs,
the recorded start monotonic time must exceed current-boot monotonic time, all
graphs/managers/private releases must already be retired, and both paths must
remain absent. Persist that current-boot proof; never recreate/adopt replacement
inodes or excuse a missing persistent directory. Fully retired false runtime
capability cleanup can similarly receipt a positively proven boot-lost file;
missing/stale authority never becomes permission to start or use legacy scope.

This does not supply a general production reset, guest idle/trigger authority or proof of
operational host/guest coupling, ingress or integrated delivery. Consumers still
refuse version-1 preparation and missing/stale version-2 authority. Never forge
a running journal/readiness marker or patch immutable units to satisfy a gate.

Use the bundled tools from a clean provenance-bound release. A reviewed source
successor used for a scoped recovery or diagnosis must be recorded separately;
never silently edit the installed bundle or call the successor its selected pin.

## Inputs and state

- Supply the exact bundle, selector, protected inventory and private journal
  paths explicitly. Site credentials enter through protected installer inputs;
  never put credentials on command lines or in diagnostic/container logs.
- The selected venue has seven rootless identities plus one rootful graph.
  Classify actual generated bind consumers, not guessed selector labels. Named
  Huly volumes belong only to the selected apps graph.
- Newly created stage directories remove inherited access/default ACLs before
  final ownership and mode assignment. Host default ACLs can contain principals
  unmapped inside rootless namespaces and break image extraction/account setup.
  Never scrub existing parents or recursively repair an existing graph.
  Cross-domain access grants are separate, explicit and journaled.
- Venue build units set host-side `TMPDIR` to their selected private SSD graph.
  Buildah can otherwise copy multi-GiB image layers through host `/var/tmp` even
  when graph storage itself is on SSD. Never lower a root-space reserve or
  retry an unchanged failed build to work around that problem. Changed unit
  bytes require a new immutable candidate; do not hand-edit installed units.
- Journal intent before mutations. Interrupted/failed operations retain their
  exact pending state; inspect it before an explicit recovery. No blind retry,
  automatic restart, or inference of completion from an inactive systemd unit.
- Quarantine is not deletion. Preserve failed graph/build receipts and account
  for retained resources until exact cleanup is reviewed. Populated data must
  never flow through an empty-stage retirement path.

## Focused build diagnosis

Once the existing preparation/image prerequisites pass, diagnose one output
without first rebuilding unrelated outputs:

```sh
python3 -B "$BUNDLE/ops/venue-local-build-images.py" \
  --bundle "$BUNDLE" --selector "$SELECTOR" \
  --site-source "$SITE_SOURCE" --ledger "$LEDGER" \
  --only-key 'p0test-r1-workloads|localhost/webservices/jupyter-notebook-build:bundle'
```

`--only-key` accepts only an existing selected user/image key, cannot combine
with recovery modes or a batch, and never retries a skipped failed build.
Omitting it retains bounded sorted discovery via `--max-new`. A completed image
is idempotently skipped. All graph, source, reserve, unit and pending-intent
checks still apply. Mutable build-time downloads make outputs discovery-only
until separately reviewed and frozen; `Pull=never` pins FROM selection, not APT,
pip, npm, SDK or other dependency downloads.

## Preserve completed outputs as release inputs

After all selected outputs are complete, the same discovery tool accepts
`--export-built-images NEW_PRIVATE_DIRECTORY`. It verifies the exact complete
plan and all selected graphs, then streams OCI image archives to an exclusive
root-owned directory with a hash-bound `manifest.json`. Identical image IDs are
exported once with all source keys retained. This publishes **canonical image
inputs**, not backups of guest/project/service state. It does not approve a
release, activate services, or silently replace the site's pins.

Full export refuses incomplete or skipped builds. To preserve one completed
output across a required source/stage change, combine export with `--only-key`:
this explicitly produces `exported-discovery-subset` and reports one exported
output separately from the whole composition count. It cannot export a missing
or skipped key, and **any pending build blocks both export modes**. Existing
output directories and unsafe parents always refuse. The saver also sets
`TMPDIR` to its selected private graph, records the exporter code SHA separately
from the build bundle provenance, and monitors host reserves plus a 120-GiB
proactive output-filesystem reserve. A failed save retains its exact
partial filename/inode receipt; it cannot be implicitly retried or imported as
a complete image. Review and freeze the successful artifact manifest into the
next site/release inputs before retiring discovery graphs or starting clean
acceptance runs. Do not discard successful outputs and repeat network builds
merely to cross an installer phase boundary.

## Freeze discovery outputs before running integration

A site can declare `localBuildImagePinsPath` with the exact relative path
`global.settings/local-build-image-ids.json`. This file has `schemaVersion: 1`
and an `images` object mapping **every selected Quadlet build-service name** to its
`sha256:<64 hex>` configuration ID. Missing/extra services, mutable references,
boolean schemas, duplicate keys and alternate paths refuse atomically.

This is an existing-generator profile, not another launcher. It retains every
recipe and build-unit identity for source review, sets those build units to
`RefuseManualStart=yes`, and removes their implicit container startup edges.
Both managed build services and other consumers of their exact generated local
tags use the frozen ID; their runtime-model entries contain no executable builds.
The two unmanaged per-project on-demand recipe entries remain untouched; they
are not host Quadlet startup units. `quadletBuildImagesFrozen` is therefore an
explicitly scoped IR marker, not a claim to freeze future user project builds.
The normal pinned-image importer must receive hash-bound OCI inputs covering all
selected IDs and imports each image only into the selected authority stores.
It uses the private selected graph for scratch and restores each exact producer
tag for dynamic consumers too, refusing existing wrong-ID aliases or failed
inventory rather than overwriting them. Frozen containers use `Pull=never`.
An image manifest alone does not prove that this installed import happened.

Use actual reviewed canonical artifacts, never the synthetic IDs exercised by
`scripts/test-frozen-build-images.py`. The discovery helper refuses these
frozen recipes before any build attempt. Unfrozen discovery is unchanged and
remains incapable of authorizing an integrated start.

## Running-integration acceptance

Before activation, prove actual installed ownership, recovery/stop authority,
listener exposure, private DNS/CA/mail/RTC routing, trigger fences and measured
physical reserves. Preserve the normal preflight refusals until the installed
lifecycle supplies the corresponding real checks. Standalone listener receipts
and inactive staging are not installed upstream/application readiness.

Acceptance requires the entire selected host stack and a fresh empty CPU-only
guest resident together, two reset-separated installations on the same frozen
inputs, then a separately reviewed real deployment. Prior serial components,
partial starts, source tests and image discovery do not count. Use scoped
results rather than a blanket success claim; actual owner/device proof remains
separate.

## Focused tests

Run `scripts/test-venue-owned-stage.py` for ACL/identity fixtures and
`scripts/test-venue-local-build-images.py` for build selection/authority fixtures.
Physical ACL tests require `setfacl` and user namespaces. Root-security fixtures
must run as root; do not mock away their ownership gates. The full
`scripts/test-runtime-generator.sh` suite additionally validates deterministic
95-service generation and native validation-only with the matching synthetic
site key. Source-only fixtures must not depend on real host accounts, linger
markers or store paths being absent.
