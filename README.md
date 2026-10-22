# SSO Stack Generator

This is the public root generator for a modular, SSO-backed self-hosted service
stack. It owns the generic build system, schema, resolver, catalog, generated
runtime model, and test runners.

It does not own site secrets, production-specific values, downstream-only
customizations, or deployable service overlays that have been extracted into
module repositories.

## Current Architecture

The stack is split across three ownership layers:

| Layer | Owns | Does not own |
| --- | --- | --- |
| Generator | Resolver, schemas, base catalog, build/deploy bundle layout, shared runtime helpers, systemd/Podman rendering, and test runners. | Site pins, plaintext secrets, downstream choices, or module-specific service source. |
| Modules | Deployable overlays for services or service groups: runtime shards, config templates, containers, tests, and component catalog entries. | Site-specific activation or secret values. |
| Site config | Site manifest, encrypted inputs, generator/module pins, and deployment target choices. | Generic generator behavior or reusable module implementation. |

The generated runtime namespace is still `webservices` for container projects,
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
systemd and Quadlet supervise the Podman-managed stack
        |
        v
verify.sh and run-tests.sh prove the deployed contract
```

Local build is intentionally secret-free. SOPS-backed site inputs are bundled in
encrypted form and decrypted only by `deploy.sh` on the target host.

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
| `runtime.overlays/` | Materialized compatibility runtime fragments in a built bundle. Deployable service overlays usually live in modules. |
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

## Optional Native Acceptance Tool Image

A site may explicitly reference a public, immutable acceptance-tool lock using
`nativeAcceptanceImagePinsPath` in its manifest. Its only supported path is
`global.settings/native-retained-acceptance-image.json`; unreferenced files are
not discovered or copied. This input is optional and does not add a managed
service, runtime build, listener, or activation authority.

The version-1 lock identifies a Linux/amd64 archive by filename, byte count,
SHA-256 and immutable image config ID, plus the selected `test-runners` source
commit/remote, Containerfile SHA-256 and two immutable build-parent identities.
The generator rejects malformed types, mutable identities, duplicate keys,
unknown fields, symlinks and oversized inputs. It requires the selected source
module and recipe to match, copies the lock into `site/`, and records its SHA-256
as `nativeAcceptanceImagePinsSha256` in source provenance. The source verifier
checks both original and bundled lock bytes against that digest.

This is source/input closure, not verification of an external archive's bytes,
its installation, native test execution, browser ownership, or application
acceptance. The operator must independently verify the actual archive and
image identity before any separately authorized use; image policy is unchanged.
Run `python3 -B scripts/test-native-acceptance-image-pins.py` for the owning
Kotlin-validator and Python-verifier source regressions (normal cached Gradle
compiler dependencies are required).

## Safety Rules

- Edit source, not generated output.
- Keep secrets encrypted until host deploy.
- Do not add repo-root `.env` files.
- Do not commit `dist/`, `out/`, Gradle outputs, Bazel outputs, or rendered
  runtime material.
- Keep destructive host-admin operations under `ops/host-admin/`.
- Keep site deployment values in the site-config repository.

For the compact engineering reference, see [docs/README.md](docs/README.md).
