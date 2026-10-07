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
`webservices.target`. A failed activation restores the previous release.

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
