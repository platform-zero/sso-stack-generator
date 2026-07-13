# Podman transition

The runtime source of truth is each selected module's `stack.runtime.yaml` plus
the site's flat `manifest.json`. Compose files remain import/reference inputs;
they are not the canonical runtime model.

## Integration ownership

`latium-integrations-stack-module` is retired for the Podman path. Caddy is
owned by `caddy-stack-module`; the site manifest and compatibility lock files
select that module directly. The retired integration repository was audited as
reference material only: its component file described the old nested selection
model, its systemd graph described Docker-era compose units, and its shared
volume file is superseded by module runtime declarations.

The active site config should contain environment values, secrets references,
and the flat module selection. It should not reintroduce hidden integration
bundles or Docker socket/controller modules.

## Generate and validate

```bash
./generate.sh \
  --site ../site-config/sites/latium/manifest.json \
  --modules-dir ../modules \
  --backend podman \
  --output /tmp/webservices-podman

./scripts/test-runtime-generator.sh
```

Use `--backend docker` to produce a Docker Compose compatibility bundle from
the same intermediate representation. `import-compose --module DIR` converts
the supported Compose subset into a module runtime file. Unsupported behavior
must be represented explicitly in the runtime model rather than hidden in a
renderer.

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

The Docker deployment remains the rollback runtime only until the same-session
cutover gate passes: stateful persistence checks, representative app smoke
checks, log/monitoring checks, backup visibility, and rollback proof. After
that gate passes, Docker implementation paths can be removed from active source
and rollback becomes Podman release rollback. JupyterHub, Forgejo Runner, and
Docker-controller test suites are deliberately deferred from the first cutover.
