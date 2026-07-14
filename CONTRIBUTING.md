# Contributing

This repo is a platform stack generator. A good change updates the source, the generated behavior, and the tests that prove it.

## Before You Start

Read:

- [README.md](README.md)
- [docs/README.md](docs/README.md)
- [modules/README.md](modules/README.md)

Check the worktree:

```bash
git status --short
```

If unrelated files are already changed, avoid touching or reverting them.

## Normal Change Flow

1. Edit source files.
2. Run focused local tests.
3. Build with the site manifest.
4. Sync `dist/` to the host.
5. Deploy on the host.
6. Run `./verify.sh`.
7. Run targeted or full `./run-tests.sh` suites when the risk justifies it.

Default build:

```bash
./build.sh --manifest /path/to/site/manifest.json
```

Default deploy:

```bash
TARGET_HOST="user@example-host"

rsync -av --no-group --delete ./dist/ "$TARGET_HOST":~/webservices/
ssh "$TARGET_HOST" 'cd ~/webservices && ./deploy.sh'
ssh "$TARGET_HOST" 'cd ~/webservices && ./verify.sh'
```

## What To Edit

Edit source:

- `runtime.overlays/`
- `stack.config/`
- `stack.containers/`
- `stack.systemd/`
- `stack.kotlin/`
- `scripts/`
- `modules/`
- `docs/README.md`

Do not edit generated output as source:

- `dist/`
- `out/`
- Gradle build outputs
- Bazel outputs
- rendered `runtime/` material

## Adding A Service Or Module

Prefer putting deployable service overlays in module repositories. Keep generic
resolver, schema, catalog, build, runtime helper, and test-runner work in this
generator.

At minimum, a user-facing service needs:

- routing
- Keycloak-backed auth
- RBAC
- homepage entry
- health check
- tests
- screenshots for web UIs
- docs

## Testing Expectations

Use targeted tests while iterating:

```bash
./scripts/test-docs.sh
./scripts/test-external-modules.sh
./scripts/test-module-runners.sh
./scripts/test-module.sh --all /path/to/module
./scripts/test-module-group.sh --all /path/to/modules-workspace
```

After deploy, use:

```bash
cd ~/webservices
./verify.sh
./run-tests.sh plan all
./run-tests.sh all
```

Run `all` when the change touches shared auth, routing, generated units, service startup, or multiple apps.

## Secrets

Do not commit plaintext secrets.

Secrets belong in the site secret store and are rendered on the target host during deploy. The local build should remain secret-free.
