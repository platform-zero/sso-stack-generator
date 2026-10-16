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

## Supported lifecycle today

| Operation | Versioned implementation | What it proves |
| --- | --- | --- |
| Inspect proposed isolation | `ops/verify-existing-host-venue.py` | Read-only selector/rendered-resource checks; never activation authority |
| Inspect past known listener refusals | `ops/inspect-existing-host-venue-beyond-listeners.py` | Static classification only, not a bypass of the normal preflight |
| Prepare inactive release | `ops/venue-install-inert.py --prepare-inactive` | One protected journal coordinating exclusive accounts, private release/env files, managers, actual binds, ACLs, volumes and inactive units |
| Prepare immutable image inputs | `ops/venue-registry-images.py`, `ops/venue-build-base-images.py` | Exact selected image/store IDs and frozen base identities, not running services |
| Discover local build outputs | `ops/venue-local-build-images.py` | Bounded selected builds and output/intermediate receipts; not frozen release inputs |
| Retire inactive release | `ops/venue-install-inert.py --retire-inactive` | Guarded reverse-order retirement of the exact inactive installation, not populated-data reset |
| Quarantine failed activation | `ops/venue-start-quarantine.py` | Stops only an exact version-2 start intent and retains data; cannot create activation authority |

The inactive installer is version 1. A version-2 installed-running lifecycle,
operational isolated host-control, installed ingress and populated-state reset
remain separate requirements. Consumers that require version-2 authority must
continue to refuse a version-1 preparation receipt. Do not synthesize a running
journal or readiness marker to satisfy them.

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

The exporter refuses incomplete, skipped or pending builds, existing output
directories and unsafe parents. It monitors existing host reserves plus a
120-GiB proactive output-filesystem reserve. A failed save retains its exact
partial filename/inode receipt; it cannot be implicitly retried or imported as
a complete image. Review and freeze the successful artifact manifest into the
next site/release inputs before retiring discovery graphs or starting clean
acceptance runs. Do not discard successful outputs and repeat network builds
merely to cross an installer phase boundary.

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
