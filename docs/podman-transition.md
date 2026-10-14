# Podman transition

The runtime source of truth is each selected module's `stack.runtime.yaml` plus
the site's flat `manifest.json`. Runtime model files remain import/reference inputs;
they are not the canonical runtime model.

## Integration ownership

`latium-integrations-stack-module` is retired for the Podman path. Caddy is
owned by `caddy-stack-module`; the site manifest and compatibility lock files
select that module directly. The retired integration repository was audited as
reference material only: its component file described the old nested selection
model, its systemd graph described legacy runtime units, and its shared
volume file is superseded by module runtime declarations.

The active site config should contain environment values, secrets references,
and the flat module selection. It should not reintroduce hidden integration
bundles or socket/controller modules.

## Generate and validate

```bash
./generate.sh \
  --site ../site-config/sites/latium/manifest.json \
  --modules-dir ../modules \
  --backend podman \
  --output /tmp/webservices-podman

./scripts/test-runtime-generator.sh
```

Each generated Podman bundle includes `source-provenance.json` with the manifest,
stack-config, and encrypted secret-store hashes (never plaintext secrets),
generator/site Git commits, and exact module remotes and commits. `bundle.json` includes its SHA-256. The `*Dirty` flags report uncommitted
source at build time; a null site commit means the input was copied out of Git.
Reject a release candidate if a revision is missing or any source is dirty:

```sh
python3 scripts/verify-podman-source.py \
  --bundle /path/to/generated-podman-bundle \
  --site /path/to/site-config/sites/latium
```

The gate also checks bundle and runtime IR hashes against the site's generator
pin, module lock, selection, and stack-config input. It deliberately rejects
locally composed bundles that do not match committed site pins. It also checks
that the site checkout is still clean at the recorded commit and that the lock
is byte-identical to the immutable `moduleManifestCommit` snapshot. The provenance
describes build inputs, not an attestation of a live installation;
compare it with the installed release and its approved site lock before cutover.

For repeated **offline preflights only**, use clean pinned module checkouts and a
new output directory on local NVMe. Each run clones the site at its exact commit,
creates independent synthetic SOPS secrets, generates and gates a Podman bundle,
and runs the installer **without** `--activate`. It compares runtime IR and
non-secret provenance across runs while requiring distinct secret-store hashes:

```bash
./scripts/rehearse-podman-preflight.sh \
  --site ../site-config/sites/latium \
  --modules-dir ../pinned-modules-20261007 \
  --output-root ../first-install-preflight-$(date +%s) --runs 2
```

The directory contains secret key material and rendered synthetic credentials:
keep it private and remove it securely after reviewing the results. These
preflights do **not** install into disposable VMs, start 95 services, exercise
SSO/Worklanes, or authorize a production cutover; those are separate gates.

For an *additional* disposable-VM installer activation check, build a
**separate two-service synthetic fixture** (one rootful and one rootless):

```bash
./scripts/make-synthetic-activation-bundle.sh \
  --output-root ../synthetic-activation-$(date +%s)
```

The private control repo's guest harness accepts this directory through
`--synthetic-activation`; it hard-rejects any other service set before allowing
`--activate` in a **new test guest only**. To exercise rollback, build a second
new fixture with `--worker-exits`, then supply it as `--synthetic-rollback`:
the guest harness must observe a failed upgrade and restore both good releases.
Never use either switch with the 95-service Latium candidate. This still does
not test a full stack install.

`import-runtime-overlays --module DIR` converts the supported runtime overlay subset into a
module runtime file. Unsupported behavior must be represented explicitly in the
runtime model rather than hidden in a renderer. The active deployment path is
`--backend podman`; compatibility bundles are transition-only and should
not be treated as the primary deploy or verify target.

## Rootful installation

Render final per-service environment files outside the generator and place
them in one directory as `<service>.env`. The installer refuses unresolved
`${...}` expressions and missing files.

```bash
sudo /tmp/webservices-podman/ops/install-podman-bundle.sh \
  --bundle /tmp/webservices-podman \
  --env-dir /path/to/rendered-env

sudo /tmp/webservices-podman/ops/install-podman-bundle.sh \
  --bundle /tmp/webservices-podman \
  --env-dir /path/to/rendered-env \
  --activate
```

Without `--activate`, the command validates the manifest, environments,
Quadlets, and generated systemd units without changing the host. Activation
installs a versioned release under `/var/lib/webservices/releases`, atomically
changes `/var/lib/webservices/current`, installs rootful Quadlets, and starts
`webservices.target`. When the selected Caddy mounts `/run/p0-control`, install,
select, configure and start the site-pinned host control role **before** activation;
a manually created socket directory does not satisfy this prerequisite. The host
unit owns its private runtime directory and orders itself before Caddy at boot.

Activation is serialized by a protected installation lock. Selected Quadlet source
builds and direct selected registry-image preparation run serially before
the complete service graph starts. Digest references and the site's explicitly
approved version tags are preserved exactly; implicit/`latest` references are
refused. Actual native configuration IDs are recorded in a protected per-bundle
ledger; cache/pull identity drift refuses replay. Tags are not described as
immutable digests, and cross-install/deployed image-ID comparison remains
required. A site can freeze those reviewed IDs in
`global.settings/registry-image-ids.json` (authority/reference to `sha256:…`);
when present, every selected registry reference must match even on its first
fresh preparation. Missing pin, mutable-tag drift or differing cache refuses
activation rather than substituting another image. Registry inventory/pull
failures refuse fallback;
selected offline images still require their protected hash-bound release inputs.
This changes build/pull concurrency, not the selected composition or service
availability requirement. Native root oneshots declare the installed standard
SOPS identity path when HOME is unset; intentional key-file selection is preserved
and a missing explicit identity does not silently fall back.

The root-only `--inspect` command reports the protected installation intent and
its SHA256. Newly created journals pin the core composition/provenance **and**
the domain manifest, site manifest/component lock, nested guest/control spec and
provenance, and registry image identity inventory (including absence when a
site-specific input is not present). These checks bind a retry on one fresh
machine; comparing two clean installs still requires review of the identical
final generator/site/control/image **pin tuple**, not machine-specific VM UUIDs.
Historical three-key receipts remain verifiable for guarded retirement, but do
not gain retroactive site/guest pin proof. A pending/failed attempt refuses blind retry: after inspecting actual
service/data state, retry the **unchanged** bundle using
`--activate --resume-intent EXACT_SHA256`. Input changes require a new reviewed
installation, not replay of an old intent. Per-release private metadata receipts
record preparing, selected units, builds, startup and activation; they contain no
credentials and do not establish functional or owner acceptance.

A stopped transient systemd installer can receive TERM in its whole cgroup while
its trap is still stopping selected units. A `failed` journal alone is **not**
quarantine proof. If the selected failed release remains `/var/lib/webservices/current`,
first review data and the exact intent SHA256 and run
`--quarantine-failed-intent EXACT_SHA256 --reviewed-data-state` as root from the
same reviewed bundle. This takes the native install lock, disables only selected
boot/auto-update triggers, gracefully stops only that release's rootful/rootless
units, and waits for the independent native unit/job/trigger verifier. It retains
data and leaves the failed intent in place; refusal means stop and inspect, never
force or silently restart. Do not invoke it for an active release, a previous
release now selected, or before the responsible installer has exited.

When a **source correction** changes inputs after terminal failure, unchanged-input
resume is deliberately insufficient. After reviewing actual data/recovery state,
use `--retire-failed-intent EXACT_SHA256 --reviewed-data-state`. This is serialized,
CAS-bound and refuses non-failed attempts, changed release fingerprints, active
selected units, queued jobs or enabled selected boot triggers. It retains volumes
and the old per-release receipt, does not restart anything, and **does not prove
data compatibility** or bypass separately gated production protection/cutover.
A new reviewed installation can then consume corrected inputs. Do not retire a
pending/unknown attempt or assert review merely to make a retry run.

On failure or cancellation the installer stops only the selected workload/build
units and retains volumes and diagnostics. If reviewed rollback is not performed,
it also disables the selected root/rootless boot targets and generated root timer,
so a later boot cannot implicitly replay the failed activation. An incomplete
quarantine is reported as requiring operator action, not success. **It does not restart a previous release by default.**
`WEBSERVICES_ACTIVATION_ROLLBACK=1` explicitly opts into release rollback only after
the operator has established compatible data/recovery coverage; incomplete scoped
stopping refuses that restart. Production data recovery is a separate gate.

Typed maintenance proposals are **not** activation authority. The independent
root approver now has a source-only read/claim API that checks the plan,
release, exact DMI UUID, synthetic marker or all three distinct current
production proof receipts, proof-byte hashes and ten-minute expiry before
atomically consuming one approval under a root-only lock. Claimed receipts
cannot be reissued for the same plan. A claim alone does **not** launch an installer. The separate typed `apply`
source queues a root worker **only on a marked synthetic isolated host**, after
rechecking the protected selected inputs and root approval. Its worker consumes
one receipt before using the native installer, records private operation status
and never restarts or rolls back on failure. This is source/fixture proof until
installed socket and real isolated application checks pass. An independent
root-selected synthetic `ts-unit` receipt also binds the current native
journal, DMI marker and exact test-runner bytes; the typed test worker refuses
non-unit/Android suites, changed selection or physical reserve loss, consumes
one receipt and retains only root0600 logs. This is source/fixture behavior,
not installed test proof or all nine suite coverage. `rollback` remains closed,
and production `apply` remains refused. Do not report a consumed
receipt as an apply, or a Worklane confirmation as independent root approval.

The root-only `ops/p0-host-install-inputs.py` prepares a separate **synthetic
isolated-only** activation-input receipt from a reviewed, root-controlled staged
bundle, a clean exact-commit control checkout, and immutable local image-input
bytes. It verifies the actual DMI UUID and private synthetic marker, uses only
the *installed trusted* host broker/guest validator code (never code from a
lane-proposed bundle), binds the site guest/control spec and image-input hash,
and refuses changed pre-existing root0600 configuration. A user-writable ancestor
such as `/mnt/lab_debian` is not acceptable: stage these authority inputs below
a root-controlled parent such as `/var/lib/platform-zero`. This preparation does
not activate a stack, constitute independent approval, or authorize production
mutation. Native end-to-end worker execution and installed denial proof remain
separately gated.

## Updates and recovery

`webservices-auto-update.timer` runs `podman auto-update --rollback` daily.
The timer only updates daemon services with `updatePolicy: registry`. A failed
run creates `/var/lib/webservices/updates.frozen`; remove that file only after
diagnosis and a successful manual validation.

Useful commands:

```bash
systemctl status webservices.target
systemctl list-dependencies webservices.target
journalctl -u 'webservices-*' --since today
podman ps --all
podman auto-update --dry-run
```

After the same-session cutover gate passes, the retired runtime is stopped and masked.
Rollback is Podman release rollback through `/var/lib/webservices/releases` and
`/var/lib/webservices-rootless/releases`; alternate runtimes are not fallback paths.
JupyterHub uses the rootless Podman API socket through its compatible client
path. Forgejo Runner post-cutover validation and controller test-suite coverage
are explicit post-refactor follow-up work tracked in
[issue #4](https://github.com/platform-zero/sso-stack-generator/issues/4) and
[issue #5](https://github.com/platform-zero/sso-stack-generator/issues/5). They
do not block closure of the completed Podman runtime migration.
