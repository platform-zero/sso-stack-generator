# AGENTS.md

## Scope

This repo owns the generic authenticated webservices platform stack.

It owns:
- edge, routing, and shared auth
- Keycloak and shared identity plumbing
- shared observability
- shared collaboration/content apps
- shared pipeline, search, and model-context services
- the platform-owned test-runner and contract suites

It does not own downstream application-specific stacks, downstream-only deploy logic, or downstream-only tests.

## Source Of Truth

Edit source, not generated output.

Primary source directories:
- `stack.compose/`
- `stack.config/`
- `stack.containers/`
- `stack.systemd/`
- `stack.kotlin/`
- `scripts/`

External deployment inputs:
- `<site-bundle>/manifest.json`
- `<site-bundle>/stack.config.yaml`
- `<site-bundle>/webservices.sops.json`

Generated artifacts:
- `dist/`
- `out/`
- Bazel outputs
- Gradle build outputs
- rendered `runtime/stack.env`

If a problem appears in `dist/`, fix the generator or bundle path that produced it.

## Public Command Surface

Local command:
- `./build.sh --manifest <path-to-manifest.json>`

Bundled host commands:
- `./deploy.sh`
- `./verify.sh`
- `./run-tests.sh`

Internal helpers:
- `./scripts/build-artifact.sh`
- `./scripts/deploy/render-runtime.sh`
- `./scripts/deploy/render-systemd-user.sh`
- `./scripts/deploy/render-systemd-user.py`
- `./scripts/deploy/install-systemd-user-units.sh`
- `./scripts/lib/systemd-compose-unit.sh`
- `./scripts/lib/systemd-docker-infra.sh`
- `./scripts/lib/wait-ready.sh`

Do not reintroduce removed top-level wrappers such as `sync.sh`, `test.sh`, `wait-ready.sh`, `render.sh`, or `sync-dist.sh`.

Default operator flow:
- local: `./build.sh --manifest /path/to/site/manifest.json`
- local: `rsync -av --delete ./dist/ <user@host>:~/webservices/`
- host: `cd ~/webservices && ./deploy.sh`
- host: `cd ~/webservices && ./verify.sh`

## Build And Deploy Contract

Site bundle:
- lives outside this repo
- is specified explicitly by manifest path
- contains only the manifest plus the files the manifest references
- is not discovered by repo symlinks or repo-local scanning

Build:
- runs locally
- requires a clean git tree
- always runs local unit tests
- produces one immutable secret-free bundle
- writes the deployable output to `dist/`
- requires `--manifest`
- does not decrypt secrets

Deploy:
- runs on the target host from `~/webservices/`
- validates the bundled inputs
- renders with SOPS on the host
- writes decrypted runtime material only into `~/webservices/runtime`
- links pre-rendered `systemd --user` units from `~/webservices/build/systemd-user`
- uses pre-rendered per-domain compose shards from `~/webservices/build/systemd-user/compose`
- uses `docker compose` as the per-service container backend, not as the host orchestrator

Verify:
- runs on the target host from `~/webservices/`
- runs readiness by default
- runs blocking verification by default with `kt stack-contract`

## Secrets

Rules:
- keep secrets encrypted in SOPS until deploy time
- render secrets on the target host, not on the dev machine
- do not add repo-root `.env` files
- do not make `dist/` a source of truth for secrets
- prefer file or stdin passing over command-line secret injection
- keep secret-store selection in the site manifest, not in repo-local discovery logic
- treat `~/webservices/runtime` as ephemeral runtime state backed by user tmpfs storage

## Onboarding Contract

- Membership is admin-created only. Do not ship public invite signup, self-service registration, or unauthenticated onboarding entrypoints.
- `onboarding.$DOMAIN` exists only for already-created authenticated users who still have Keycloak required actions to complete.
- Users marked with `onboarding_required` must be redirected to the authenticated onboarding page at `https://onboarding.$DOMAIN/`.

## Testing

Preferred generator test entrypoints:
- `./scripts/test-component-selection.sh`
- `./scripts/test-external-modules.sh`
- `./scripts/test-module-runners.sh`
- `./scripts/test-module.sh --all /path/to/module`
- `./scripts/test-module-group.sh --all /path/to/modules-workspace`
- `./scripts/test-docs.sh`

The Playwright/test-runner package is module-owned. Run it from the
test-runners module checkout during module development, or from the generated
bundle after module materialization.

Keep module-specific service contracts in the owning module's `tests/contract.sh`
and use `smoke` metadata to distinguish local smoke from deployed-only
verification.

Important constraints:
- Playwright and deep auth suites depend on deployed runtime env and compose DNS
- the compose project name stays `webservices`
- remote deployment verification belongs to `./verify.sh`, not ad hoc wrappers

## Screenshot And Visual Evidence Standard

Screenshot coverage for public and optional modules is part of the platform
contract. It is not acceptable to pass visual work by hiding failures.

Rules:
- Public and optional service modules with browser-visible capability need real
  screenshots unless the module is explicitly classified as private or
  non-browser/API-only.
- Private modules are excluded from public screenshot requirements by default;
  do not use that exception for public optional modules.
- Required screenshots must be captured from the real deployed app/module, not
  from fake HTML, placeholder cards, mocked images, generic dashboards, blank
  states, setup wizards, or login pages.
- Screenshots must contain realistic synthetic data or clear authenticated
  operational state that proves the module capability.
- If auth, onboarding, seed data, app configuration, or server behavior prevents
  a real screenshot, fix the harness and/or the owning server-side source/config.
  Do not mark the module done, demote the module, or substitute fake evidence.
- Every screenshot task must include an explicit coverage matrix: required
  module, expected artifact path/name, evidence expected in the image/page, and
  pass/fail state.
- File existence is not enough. Inspect the emitted artifacts for visual
  usability and evidence: correct app, populated state, readable crop, no login
  redirect, no empty/error/setup screen, no fake placeholder.
- Keep iterating on the failing target until the screenshot emits as a real,
  usable artifact. Do not switch to unrelated work while required screenshots
  are missing or fake.

Expected remediation loop:
1. Enumerate required public/optional screenshot targets from the module and
   route inventories.
2. Compare required targets with emitted artifacts.
3. Run the narrow failing Playwright screenshot test.
4. Inspect screenshot, trace/logs, and server logs.
5. Patch harness, seed data, module config, or server-side code.
6. Redeploy/restart the minimum affected service set.
7. Re-run the narrow target.
8. Repeat until every required screenshot is real, populated, and usable.

## Practical Rules

- Prefer shell for repo scripting unless it becomes unreasonable.
- Prefer minimal explicit flow over convenience wrappers.
- Prefer fixing generators over patching outputs.
- Preserve the `webservices` naming.
- Commit each coherent source change set once it is implemented and verified;
  do not leave completed edits uncommitted while moving on to unrelated work.
- Keep destructive host-admin operations under `ops/host-admin/` and out of the bundled deploy UX.
- Prefer direct `ssh <user>@<host> "command"` for remote inspection or repair.
- Do not guess remote usernames or hosts if the user has not provided them.

## When In Doubt

Use this order:
1. Fix source files.
2. Run `./build.sh --manifest /path/to/site/manifest.json`.
3. Copy `dist/` to `~/webservices/` on the host.
4. Run `cd ~/webservices && ./deploy.sh` on the host.
5. Run `cd ~/webservices && ./verify.sh` on the host.
6. Only then investigate runtime-specific failures.
