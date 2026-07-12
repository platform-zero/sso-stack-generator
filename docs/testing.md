# Testing

The generator uses layered tests so failures point to the smallest responsible
surface.

## Repository Hygiene

The CI hygiene job checks required publication files, private path leaks, shell
syntax, ShellCheck, deploy-state guards, environment-file security, and
documentation links.

```bash
git ls-files 'scripts/**/*.sh' 'ops/**/*.sh' 'stack.config/**/*.sh' | xargs -r -n1 bash -n
git ls-files 'scripts/**/*.sh' 'ops/**/*.sh' 'stack.config/**/*.sh' | xargs -r shellcheck -S error -s bash
./scripts/test-deploy-state.sh
./scripts/test-env-file-security.sh
./scripts/test-docs.sh
```

## Module-Owned TypeScript Tests

The Playwright test-runner package is provided by the external `test-runners`
module and is available after module materialization or inside a built bundle.
From a public generator-only checkout, run module tests in that module
repository instead of expecting `stack.containers/test-runner` to exist here.

```bash
npm ci
npm run build
npm run test:unit
```

## Stack Module Contracts

Stack modules own service-specific assumptions: their templates, shell scripts,
Dockerfiles, expected artifact names, healthcheck assumptions, and local smoke
status. The generator owns the shared schema, resolver, overlay materialization,
component selection, bundle packaging, and deployed verification orchestration.

Every stack module must declare `runtimeDependencies`, `contracts`, `smoke`, and
`testAssets` in `stack.module.json`. Use the strict runner when validating a
module checkout:

```bash
./scripts/test-module.sh --all /path/to/module
./scripts/test-module-group.sh --all /path/to/modules-workspace
```

`smoke: required` means `tests/smoke.sh` must exist and run. `smoke:
external-only` or `smoke: unsupported` must include a concrete
`smokeUnsupportedReason`; deployed browser, SSO, DNS, TLS, and screenshot suites
remain generated-bundle responsibilities.

## Kotlin Tests

Kotlin service modules are built and tested in their source or stack-module
repositories, then materialized into the bundle.

```bash
./gradlew test shadowJar --no-daemon
```

## Artifact Tests

The release artifact path validates generated contracts, package assembly, and
selected component output after the configured modules have been materialized.

```bash
./scripts/test-component-selection.sh
./scripts/build-artifact.sh
```

## Deployed Stack Tests

After deployment, the generated `verify.sh` script runs readiness checks and the
blocking stack-contract suite. Full end-to-end and visual suites should be run
against representative deployed environments before release decisions that
touch authentication, routing, screenshots, or service startup behavior.

The bundled `run-tests.sh` uses the managed test-runner container. Commands that
look like metadata queries, including `list` and `plan`, may still build the
test-runner image and start a short-lived container so suite discovery matches
the materialized bundle.

Full-suite orchestration should keep running independent suites after an
individual suite fails, then report the complete status set at the end.
Deployment-safe `all` runs should not include non-deployment source suites such
as `source-unit` or recovery-only suites unless the target explicitly asks for
them.

Artifact collection is part of the test contract. A completed run should retain
the wrapper log, per-suite reports, JSON/JUnit files, screenshots, and failure
attachments such as `test-failed-*.png`, `video.webm`, traces, and
`error-context.md`. If the top-level log reports a failure, copied per-suite
JSON/JUnit artifacts must preserve that failure rather than showing a clean
subgroup.
