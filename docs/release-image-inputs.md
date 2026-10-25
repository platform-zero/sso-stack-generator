# Immutable release image inputs

The native installer deliberately refuses selected bare `sha256:…` images without
explicit root-owned, hash-bound image inputs. Do not bypass that check. Packaging
is **artifact/source-binding proof only**, not installer, owner/SSO/device, recovery,
or clean-install acceptance. Complete acceptance remains **0/2** until the existing
installer/journal and full acceptance procedure establish otherwise.

Application data, container writable layers, whole stores, protected/original host
caches and disposable experiments are not release inputs. This workflow neither
preserves experiments nor authorizes access to their stores. It performs no builds,
container starts, pulls, deletes, tag fallback or installer/journal writes.

## Freeze owning source before packaging

1. Treat mutable/network-fetching builds as **discovery**, never release pins.
   The authorized producer must prove each exact configuration ID in its own
   selected authority, using the existing journal/idle/ownership/CAS gates. An ID
   found in another account's store is not availability proof for that account.
2. Review the producer recipes, dependency/base pins, selected generator/module
   commits and discovery outputs. Freeze the reviewed IDs in site source via the
   manifest's `localBuildImagePinsPath`:

   ```json
   {"schemaVersion": 1, "images": {"selected-producer": "sha256:<64 lowercase hex>"}}
   ```

   Include exactly every selected emitted build producer, keyed by service name.
   In the standalone host profile this means **all selected services with a build
   recipe**, including `lifecycle: on-demand` / `quadletManaged: false` producers;
   emission/freeze does not authorize automatic startup. The set is derived from
   the selected IR, not a fixed count/name allowlist: a newly selected security
   Caddy recipe also requires its own producer pin. Legacy profiles retain their
   managed-Quadlet producer filter. Shared-image producers remain separate keys
   even when their IDs are identical. Standalone manifest, bundle and domain
   metadata must agree on that profile.
   Commit/freeze through the integration owner, not through this packaging tool.
3. Regenerate with the existing generator from clean pinned generator, site and
   module source. Generated IR must have `quadletBuildImagesFrozen: true`, exact
   `image == frozenBuildImage`, and `updatePolicy: pinned` for producers and all
   frozen consumers. Generated recipes remain inert; no startup rediscovery.
4. The supply owner binds the reviewed archives to **this regenerated bundle**.
   Old discovery-bundle hashes do not automatically authorize a new source freeze.
   Review/rebind through the existing journal authority; do not fabricate approval
   by editing its receipt. Archive bytes/configuration IDs must not change.
5. Package only the selected bare immutable IDs. Registry references and build-base
   pins retain their separate existing preparation/own-store verification flows.
   A changed image, source/module pin or selected composition resets accepted runs.

The packager checks bundle IR/provenance/manifest hashes, clean committed owning
source metadata, exact site producer pins, every frozen consumer, and exact selected
per-image authority sets. It does not read original checkouts, keys, encrypted secret
stores or runtime environments, run Git, regenerate Kotlin output, or claim that
source commits independently reproduce image bytes.

## Inspect the required binding (read-only)

Use `runtime-generator/podman-ops/package-release-images.py --bundle BUNDLE
--describe-selection` on an authorized root-owned staging bundle. This emits only:

- `binding`: `bundleIrSha256`, `sourceProvenanceSha256`, `siteManifestSha256`,
  `domainMetadataSha256`, `localBuildPinsSha256` (null when there are no producers).
- `imageAuthorities`: exact `sha256:…` → sorted Linux authority names, including
  non-producer consumers and `root` where selected.

There is no mutation or image operation. Do not substitute a different authority
because it already has the image. Bundle root and output parent must be root-private;
all traversed ancestors must be root-owned directories, not symlinks or writable
by other users. Input files must be root-owned regular, single-link files, not
writable by other users. Path traversal, linked ancestors and hardlinks fail closed.

## Rebind previously qualified immutable producer artifacts

The existing `export-selected-images.py` producer also supports an **artifact-only**
mode. It does not start a builder or manager, access any image store, export an
actor graph, manufacture an operation permit, or prove availability in a target
actor's store. The original artifacts and producer inputs remain read-only.
Use it only with an independently reviewed, protected record of an actual complete
producer run—not fixtures, a partial build, a tag, or a self-authored approval.

```sh
python3 export-selected-images.py --bundle /root-owned/new-bundle \
  --rebind-qualified-artifacts \
  --source-bundle /root-owned/original-producer-bundle \
  --public-build /root-owned/original-public-build \
  --producer-record /root-owned/producer/producer-results.json \
  --producer-sha256 <independently-reviewed-record-sha256> \
  --image-inputs /root-owned/original-package/image-inputs.json \
  --image-inputs-sha256 <independently-reviewed-input-sha256> \
  --output /root-private/artifacts/new-child
```

The owner checks the original complete public-tree hash and file count, the
producer's original IR binding, exact selected producer coverage, every recipe
hash, build context/options, and all effective COPY sources across build stages.
Current and original COPY bytes and canonical execute bits must match. Unreferenced
configuration changes can differ; there is no path/name exception list. New COPY
syntax, dynamic/escaping sources, ADD, ONBUILD, RUN mounts, Dockerignore files,
external-stage copies and unrecorded build arguments fail closed for owning review.
Copied dependency manifests and immutable recipes remain byte-identical; this mode
never resolves mutable build dependencies again or claims reproducible rebuilding.

It independently checks the selected archive bytes and OCI config/ordered DiffIDs
against the protected producer outputs, preserves exact non-producer immutable
consumer identities, and derives the new transport authority map from the new clean
bundle. The old package/source binding is not accepted as the new binding. All source
CAS is repeated, COPY trees are re-enumerated, archives are copied without hardlinks,
and input/output authorities must be disjoint. Reserve and time gates apply; a
prospective archive copy must leave 50 GiB on its actual staging filesystem, in
addition to the host reserve floors. An interrupted child remains PENDING and is
not reusable. The packager refuses even a dangling PENDING marker in offline supply.

Normally successful output contains `supply.json` and bounded
`source-qualification.json`. To avoid a second full-size archive copy, the same
producer accepts `--package-output`: after qualification it calls the existing
packager internally, producing the normal `image-inputs.json`,
`release-image-proof.json` and `source-qualification.json` directly. The new proof
mode is `qualified-artifact-rebind`; the consumer additionally verifies the
protected qualification report's hash, exact selected producer set (including
on-demand recipes), OCI proofs, new binding and trusted bundled qualifier SHA.

An optional `--archive-source /exact/original-package` supplies **opaque data
only** when an archive filesystem has operator-owned ancestors. All executable
code, candidate/producer controls, original public build tree and reviewed input
manifest must first be hash-verified and staged beneath fully protected Root-owned
ancestors. Preserve the manifest basename (`image-inputs.json`) in that control
staging; its bytes must match the original archive directory's manifest. The data
reader opens every ancestor and leaf without following symlinks, retains kernel
FDs, refuses linked/nonregular/oversized files or PENDING sources, and rechecks
held/named inode/stat identity. Protected expected archive hashes and actual OCI
closure authenticate the bytes; mutable ancestors never authenticate Root code,
operation authority or an actor store. Source archives are never written, adopted
as a cache, executed, or made trusted by changing original permissions. Final
copied package files still require the normal fully protected Root ancestry.

With both `--package-output` and an explicit `--archive-source`, the additional
`--reference-qualified-archives` option publishes **only** the three small
protected control files. Its `qualified-artifact-references` proof binds the
qualification report's exact archive-filename-to-absolute-DATA-path map. The
original archives are not copied, moved, hardlinked, symlinked or rewritten.
Every source still passes actual byte/config/ordered DiffID qualification. This
mode reserves metadata space rather than a duplicate archive's bytes; all host
reserve floors remain mandatory.

The canonical consumer requires protected Root controls and the exact bundled
qualifier owner/new binding/producer coverage/zero-credit fields as before. Only
in this explicit proof mode may payload archives have opaque operator-owned
ancestry. It opens all ancestors/leaves without following links, requires exact
hashes/sizes and real OCI closure, pins source directory and file identity, rejects
PENDING (including dangling markers), and rechecks namespace/file CAS through
import and each held stdin FD. The source paths confer no executable, store or
operation authority. Any data-path/content change requires new qualification;
never patch sealed control files or select an actor store as the data source.
Existing offline-supply/cache and native custody gates are not relaxed.

These are source/artifact transport evidence with zero integrated-install credit,
not journal approval, selected-store availability or deployed behavior. Review the
new supply SHA-256 and use the existing offline packaging command below. Canonical
installation, per-actor import/verification, native custody, and actual acceptance
are still mandatory. Do not relocate runtime roots or modify old source/supply to
make space; choose an explicitly owned, adequately sized artifact destination.

## Preferred path: offline hash-pinned supply

No image runtime is needed for this mode. The authorized supply owner provides one
plain OCI tar per distinct selected ID and a protected sibling `supply.json` with
exactly these keys (placeholder hashes below are explanatory, not accepted inputs):

```json
{
  "schemaVersion": 1,
  "purpose": "release-image-supply",
  "binding": {"<all binding fields>": "<from describe-selection>"},
  "imageAuthorities": {"sha256:<config hex>": ["<every selected authority>"]},
  "images": [{
    "image": "sha256:<config hex>",
    "archiveFilename": "<sibling basename>.tar",
    "archiveSha256": "<64 lowercase hex; entire archive>",
    "archiveBytes": 12345
  }]
}
```

The binding/authority objects must equal the read-only selection output exactly.
Every selected image occurs once; no extra, missing or duplicate image/archive is
allowed. A filename is a simple non-hidden sibling basename ending in `.tar`, not
a path. Size is a positive integer, not a boolean. Review the supply file's SHA-256
outside that file and pass it explicitly; self-asserted hashes are not CAS proof.

Authorized operator invocation (not an instruction to run it during source review):

```sh
python3 runtime-generator/podman-ops/package-release-images.py \
  --bundle /root-owned/frozen-bundle \
  --supply-inputs /root-owned/supply/supply.json \
  --supply-sha256 <reviewed-supply-file-sha256> \
  --output /root-private/releases/fresh-child
```

The tool validates size/hash/source scope before staging, copies rather than
hardlinks, verifies actual OCI contents, and rechecks inode/device/size/mtime/ctime/
hash CAS before publication. Offline supply cannot combine with cache/export flags.
A supply configuration is an artifact contract, **not** a replacement for producer
journal approval or proof of any target authority's installed store.

## Optional path: dedicated selected export cache

Never point this mode at original/authored/protected host caches, the default
Podman store, lane stores, or a cache containing unrelated images. The tool does
not provision/adopt/populate a cache. Availability and authorization of such a
**dedicated** source are remaining producer/integration responsibilities.

Required artifacts, already provided by the authorized supply/installer authority:

1. An explicit root-private plain graph directory with exactly the selected
   configuration IDs in `overlay-images/images.json`, and no unrelated image IDs.
   This inventory is hash-pinned and must remain unchanged through export.
2. A protected single-link `<graph>/.release-image-source.json`:

   ```json
   {"schemaVersion": 1, "purpose": "selected-release-export-cache", "graphRoot": "/exact/graph"}
   ```

3. An already-created empty, root-private run directory, disjoint from the graph.
4. A protected export configuration/receipt with exactly these keys:

   ```json
   {
     "schemaVersion": 1,
     "purpose": "release-image-export",
     "binding": {"<all binding fields>": "<from describe-selection>"},
     "imageAuthorities": {"sha256:<config hex>": ["<every selected authority>"]},
     "graphRoot": "/exact/graph",
     "runRoot": "/exact/fresh-run-root",
     "sourceMarkerSha256": "<marker-file-sha256>",
     "inventorySha256": "<inventory-file-sha256>"
   }
   ```

   Its independently reviewed hash is mandatory. Schema, purpose, bundle binding,
   complete authority map, exact graph/run paths, marker hash and inventory-hash
   syntax are checked **before any inventory stat/hash/content read**. Only a
   matching scope permits reading the bounded inventory and checking its reviewed
   hash and exact selected ID set. This transport receipt cannot authorize cache
   adoption or supersede the existing producer journal/marker.

```sh
python3 runtime-generator/podman-ops/package-release-images.py \
  --bundle /root-owned/frozen-bundle --source-store /exact/graph \
  --run-root /exact/fresh-run-root \
  --source-receipt /root-owned/export-config/receipt.json \
  --source-receipt-sha256 <reviewed-receipt-file-sha256> \
  --output /root-private/releases/fresh-child --image-timeout 600
```

Legacy unreceipted `--source-store` invocations now fail closed. This mode uses only
explicit Buildah graph/run roots and immutable configuration IDs; push destinations
are local OCI archives. It supplies a minimal environment and empty registry auth
file instead of inheriting operator credentials, remote authorities or registry
logins. Explicit transient storage/container configuration disables additional image
stores rather than inheriting system cache fallbacks. Dedicated run-root/scratch
files may remain after interruption; there is no
unrelated cache, service, image, data or journal cleanup. Never relax the inventory
CAS if a runtime version mutates it: investigate through the owning integration
and use reviewed offline supply if appropriate.

This aggregate root-owned cache mode is **not** the per-actor rootless exporter.
It cannot adopt actor-owned graphs or prove source-store availability for the
selected actors merely by labeling `imageAuthorities`. Actual per-actor export,
namespace/backend/runroot compatibility, source inventory CAS and protected
root-owned offline-supply publication remain separate integration responsibilities
under the existing journal/installer authority. No manager, service or admission
replacement is introduced here.

## OCI integrity and publication contract

Without filesystem extraction, validation binds:

1. The entire supplied/staged tar's size/hash and stable file identity.
2. The single OCI index descriptor's actual manifest size/digest/media type.
3. That manifest's actual config size/digest/media type to the **selected immutable
   config ID**, Linux/amd64 platform, and `rootfs.type == layers`.
4. Every manifest layer's actual compressed size/digest and permitted media type.
5. The **ordered uncompressed layer hashes** to `rootfs.diff_ids`, with exact count.

Plain tar and gzip layer media types are supported. Zstd, foreign/external or
embedded descriptors, nested/multi-image indexes, wrong platforms, duplicate JSON
keys, duplicate/escaping/linked/extended archive members, unrelated files/directories
and nonzero trailing tar content fail closed. Limits: 2 MiB metadata, 4,096 outer
members, 1,024 layers, 64 GiB uncompressed per layer, 256 GiB aggregate/archive.
Layer contents are hashed, not materialized; this is not a container malware scan
or proof of a safe filesystem/app. No optional decoder or registry fallback runs.

Packaging enforces a one-hour overall deadline and per-export 1–3,600 second
bound (600-second default), plus 50 GiB free on `/` and output storage, 100 GiB on
`/mnt/stack`, and 16 GiB available RAM. Reserve/deadline/interrupt failure cancels
only the owned exporter process group, retains pending artifacts, and never
implicitly retries/reuses an output. Reserves and partial-file type/link/size are
checked before exporter spawn, on each polling iteration (at most a one-second
sleep), on observed leader exit and after teardown, before archive hashing. A
partial over 256 GiB is refused immediately when observed; this is a sampled
refusal bound, **not** a filesystem quota or a guarantee of zero overshoot. Supply
files with a wrong declared size are refused before hashing; offline copy refuses
any block that would exceed the reviewed size or archive cap. Verification/copy
streams also check reserves.

Cancellation retains the direct child as waitable (`waitid` with `WNOWAIT`), so
its numeric group identity stays reserved even after leader exit. Teardown sends
SIGTERM to that owned group, allows up to five seconds of grace, then sends
SIGKILL before reaping the leader; it checks group disappearance for at most five
more seconds. The retained zombie leader can itself keep the group present during
the grace interval, so successful exports may also pay that grace interval. No
further group signal is sent after reaping, when the numeric ID could be reused.
Failure to observe quiescence (including unreaped descendant zombies) refuses
publication; there is no assumption that leader exit means descendants stopped.
Repeated INT/TERM/ALRM cancellation is deferred through teardown and removal of
only the newly created private export configs. Spawn deferral does not leave a
blocked signal mask inherited by the exporter. These guarantees concern members
of the owned session/process group, not descendants that deliberately escape it;
this is not a sandbox or a new process-reaper service.

Successful output contains:

- `<config hex>.oci.tar`: verified archives, unchanged immutable IDs.
- `release-image-proof.json`: exact source binding/authorities, reviewed input hash,
  packager source hash, `imageInputsSha256` binding the installer-facing manifest,
  and actual manifest/config/ordered DiffID proofs. It always
  states `activationAuthorized: false`, `acceptedIntegratedInstalls: 0`.
- `image-inputs.json`: installer-compatible schema 1 image/archive hashes and sizes,
  published last after all selected images and source CAS checks succeed.

Files and directory entries are fsynced. `PENDING` is retained on failed/interrupted
runs and removed only after complete manifest publication. **Consumers must require
PENDING absent**, the exact reviewed manifest/proof hashes (including agreement
with `imageInputsSha256`) and the unchanged selected bundle. A crash after manifest rename but before PENDING removal is conservatively
pending; do not auto-replay or delete that marker to promote it. Existing installers
that only parse `image-inputs.json` still need this outer publication check in their
own journal-authorized integration. A test pass does not supply that installed proof.

## Remaining actual-export and installation checks

Source fixtures do not prove a real Buildah/Podman version preserves config bytes,
uses supported OCI media types or leaves the selected inventory CAS unchanged.
The authorized producer must check those properties, actual archive sizes, reserve
behavior and interrupt preservation on the exact dedicated source. No protected
cache export is needed or permitted to satisfy these checks. The existing installer
must independently admit/import the hash-pinned artifacts and inspect the exact ID
in **each** selected own store, with existing journal/owner/admission gates intact.
No acceptance credit follows from packaging or shared-image deduplication.

Source-only regression command (no live store or app calls):

```sh
PYTHONDONTWRITEBYTECODE=1 timeout 120s python3 scripts/test-package-release-images.py
```

The Linux process fixtures run only disposable Python parents/children. A
fixture-local subreaper reaps its synthetic orphan so the test can prove full
group disappearance, TERM-responsive/already-exited/TERM-ignoring leaders,
SIGKILL of the TERM-ignoring writer, repeated interrupts and config removal.
Other fixtures mock runtime export, ownership/reserves as identified in the test
source, while exercising actual synthetic OCI bytes, ordered DiffIDs and CAS.
Wrong-scope receipt tests forbid even stat/open/hash access to the inventory and
assert zero export/output staging. Synthetic 15-producer and additional Caddy
cases test exact producer-set closure, not actual selected deployment contents.
None of these tests prove live runtime export, host reserve behavior or installed
admission, and they do not promote the **0/2** acceptance status.

## Rebind labels when changing site account policy

Registry/build-base pins include Linux authority labels as well as image identity.
Use explicit old/new policies, review the new file and commit it as site source:

```sh
python3 scripts/rebind-image-authorities.py \
  --from-policy old-stack.config.yaml --to-policy new-stack.config.yaml \
  --pins registry-image-ids.json --output registry-image-ids.new.json
```

The command also supports build-base pin objects. It requires identical logical
domain membership, refuses unknown/colliding accounts, preserves immutable IDs and
registry references, and does not overwrite existing output or call a runtime.
It is not image availability or installed proof.
