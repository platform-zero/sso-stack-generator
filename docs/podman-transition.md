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
