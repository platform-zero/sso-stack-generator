# SSO Stack Generator

This is the public root generator for a modular, SSO-backed self-hosted service
stack. It owns the generic build system, schema, resolver, catalog, generated
runtime contract, and test runners.

It does not own site secrets, production-specific values, downstream-only
customizations, or deployable service overlays that have been extracted into
module repositories.

## Current Architecture

The stack is split across three ownership layers:

| Layer | Owns | Does not own |
| --- | --- | --- |
| Generator | Resolver, schemas, base catalog, build/deploy bundle layout, shared runtime helpers, systemd/Compose rendering, and test runners. | Site pins, plaintext secrets, downstream choices, or module-specific service source. |
| Modules | Deployable overlays for services or service groups: Compose shards, config templates, containers, tests, and component catalog entries. | Site-specific activation or secret values. |
| Site config | Site manifest, encrypted inputs, generator/module pins, and deployment target choices. | Generic generator behavior or reusable module implementation. |

The generated runtime namespace is still `webservices` for Compose projects,
systemd units, paths, labels, and tests. That runtime name is separate from the
repository identity.

## Build Flow

```text
generator source + site manifest + pinned modules
        |
        v
local build resolves catalogs and runs source checks
        |
        v
secret-free dist/ bundle
        |
        v
host deploy renders secrets and runtime config
        |
        v
systemd --user supervises Docker Compose shards
        |
        v
verify.sh and run-tests.sh prove the deployed contract
```

Local build is intentionally secret-free. SOPS-backed site inputs are bundled in
encrypted form and decrypted only by `deploy.sh` on the target host.

## Clean site-lock flow

The foundation migration uses one `site.lock.json` as the sole composition
input. Each entry pins a module Git URL and commit; each module provides a
`module.json` descriptor with versioned capabilities, service routes/volumes,
configuration schema, overlays, and verification commands. The builder creates
a temporary checkout for every module, never reads `dist/`, `out/`, or host
state, and writes `bundle.tar`, `bundle.tar.sha256`, and `bundle.json`.

```bash
./site-build.sh --site-lock /path/to/site.lock.json --output /tmp/site-release
./scripts/site/deploy-site.sh --site-lock /path/to/site.lock.json --bundle-dir /tmp/site-release \
  --readiness-command './verify.sh'
```

The deploy command uploads only the completed bundle to `gerald@192.168.0.11`.
The host verifies the checksum, artifact manifest, and lock hash, extracts a
new release under `~/webservices/releases`, runs the configured readiness
command, then atomically updates `~/webservices/current`. It never clones or
builds modules. The prior release target is recorded for rollback; activating
it is a symlink update after its own verification:

```bash
WEBSERVICES_RELEASE_ROOT=~/webservices ./scripts/site/rollback-release.sh
```

## Command Surface

Build from a source checkout:

```bash
./build.sh --manifest /path/to/site/manifest.json
```

Deploy from the generated bundle after syncing `dist/` to the target host:

```bash
cd ~/webservices
./deploy.sh
./verify.sh
./run-tests.sh list
./run-tests.sh plan all
```

`run-tests.sh` answers are produced by the managed test-runner container. Even
metadata-oriented commands such as `list` and `plan` may build
`stack/test-runner:local-build` and start a short-lived container so the output
matches the materialized bundle.

Targeted runtime test iteration uses the platform test runner after modules are
materialized or from a built bundle:

```bash
./run-tests.sh source-unit
./run-tests.sh changed
./run-tests.sh kt-tests stack-contract
./run-tests.sh kt-plan stack-contract
./run-tests.sh kt-one <id> stack-contract
```

The bundled `./run-tests.sh` supports `list`, `plan [target]`, `changed`,
`source-unit`, `kt-tests [suite]`, `kt-plan [suite]`, `kt-one <id> [suite]`,
and `all`. Use focused targets while iterating and `./verify.sh` before trusting
a deployment.

## Repository Map

| Path | Purpose |
| --- | --- |
| `build.sh` | Public local build entry point. |
| `scripts/` | Build, resolver, deploy rendering, module, and validation helpers. |
| `modules/` | Public module catalog, group definitions, and module metadata schema. |
| `stack.kotlin/` | Materialized Kotlin services in a built bundle. Source lives in modules. |
| `stack.compose/` | Materialized Compose files in a built bundle. Deployable service overlays usually live in modules. |
| `stack.config/` | Base config, schemas, Caddy/Keycloak templates, and runtime helper inputs. |
| `stack.containers/` | Materialized custom container contexts in a built bundle. |
| `stack.systemd/` | Source graph for generated systemd user units. |
| `global.settings/` | Shared non-secret defaults for generated bundles. |
| `modules/` | Generator-owned module catalog, schemas, and pull/test helpers. |
| `docs/README.md` | Compact architecture, build, test, and migration notes. |
| `dist/`, `out/`, `build/` | Generated output. Do not edit as source. |

## Module Catalog

The public module inventory lives under [modules/README.md](modules/README.md).
The generator resolves the base component catalog plus module-provided catalogs,
then emits only the manifest-selected components.

Site-specific module selection and exact commit pins belong in the site
configuration repository, not in this public repo.

## Safety Rules

- Edit source, not generated output.
- Keep secrets encrypted until host deploy.
- Do not add repo-root `.env` files.
- Do not commit `dist/`, `out/`, Gradle outputs, Bazel outputs, or rendered
  runtime material.
- Keep destructive host-admin operations under `ops/host-admin/`.
- Keep site deployment values in the site-config repository.

For the compact engineering reference, see [docs/README.md](docs/README.md).
