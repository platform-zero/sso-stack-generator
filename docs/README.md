# Generator Notes

This directory intentionally contains one concise public reference. Detailed
service runbooks, site procedures, and deployable service docs belong in module
or site-config repositories.

## Ownership Boundaries

The generator owns:

- manifest and module resolution
- schemas and component catalog merging
- secret-free bundle construction under `dist/`
- deploy-time rendering helpers
- generated systemd user unit and Podman bundle contracts
- shared Caddy, Keycloak, runtime, and test-runner plumbing

Modules own deployable overlays:

- module `stack.config/components.json` entries
- runtime shards, config templates, custom containers, and tests for the module
- module-specific service documentation
- explicit override declarations when replacing generator files

Site config owns:

- site manifest and encrypted SOPS inputs
- generator and module pins
- selected components for a site
- deployment target choices and site-specific operating notes

## Build And Runtime Contract

`./build.sh --manifest <manifest.json>` runs locally. It resolves the site's
pinned module manifest, merges component catalogs, runs source checks, and
writes a secret-free deploy bundle to `dist/`.

`./deploy.sh` runs on the target host from the synced bundle. It decrypts the
bundled site inputs with SOPS, renders runtime material under
`~/webservices/runtime`, validates the generated Podman bundle with the
rendered env, installs generated `systemd --user` units, and reconciles the
requested target.

The normal operator path is:

```bash
./build.sh --manifest /path/to/site/manifest.json
rsync -av --no-group --delete ./dist/ user@host:~/webservices/
ssh user@host 'cd ~/webservices && ./deploy.sh'
ssh user@host 'cd ~/webservices && ./verify.sh'
```

Host reset tools stay under `ops/host-admin/`. Destructive helpers such as
`purge-webservices-stack.sh` are not part of the normal deploy UX. Use
`--print-only` before a purge and use `--skip-labware-runtime` only when keeping
workspace runtime data is intentional.

`scripts/testdev/` is for disposable local validation, normally on labware with
nested container-runtime compatibility. Latium remains the real deployment
target and should be exercised through the generated deploy and verify scripts,
not the testdev harness.

## Resolver And Modules

Sites may pin a private module-manifest repo from `.webservices-generator.json`.
The generator resolves that manifest, checks each module's metadata against
`modules/stack.module.schema.json`, copies allowed source paths, and merges
module component catalogs with the base catalog.

Allowed module contribution paths are intentionally narrow: `global.settings/`,
`runtime.contract/`, `stack.config/`, `stack.containers/`, `stack.kotlin/`,
`stack.js/`, `stack.systemd/`, `scripts/lib/`, `scripts/modules/`, and
`docs/modules/`. A module that replaces a generator file must declare that file
in its `overrides` list.

See [../modules/README.md](../modules/README.md) for the catalog and pull/test
helpers.

## Auth And Runtime Standards

Caddy is the public edge and Keycloak is the shared identity provider. Services
should use native OIDC when practical or the shared edge auth pattern when the
app needs protection outside its own login flow.

Current Keycloak-backed service expectations include:

| Service | Identity status |
| --- | --- |
| SOGo | Restored as Keycloak-backed groupware |
| Jellyfin | App SSO with Keycloak group authorization |
| Donetick | Keycloak edge-auth and app OAuth2 client wiring |
| Vaultwarden | Keycloak SSO entry path derives email |
| ERPNext | Keycloak edge-auth and app OAuth2 client wiring |
| Disposable Workspaces | Keycloak edge-auth to the dispatcher |

Secrets stay encrypted until host deploy. Rendered files under
`~/webservices/runtime` are runtime state, not source.

## Test Runner

The source and bundled runners expose the same broad surface:

```bash
./run-tests.sh list
./run-tests.sh plan all
./run-tests.sh changed
./run-tests.sh source-unit
./run-tests.sh kt-tests stack-contract
./run-tests.sh kt-plan stack-contract
./run-tests.sh kt-one <id> stack-contract
./run-tests.sh all
```

The help forms are `plan [target]`, `kt-tests [suite]`, `kt-plan [suite]`, and
`kt-one <id> [suite]`. `all` runs every registered check and is intentionally
broad. Browser and deep auth tests require a deployed runtime because they
depend on real domains, Caddy, Keycloak, cookies, and running containers.

## Adding Or Moving Services

Prefer adding deployable service overlays in module repositories. Keep generic
resolver, schema, catalog, build, runtime helper, and shared test-runner changes
in this generator.

When moving old generator-owned service material into a module, remove duplicate
public docs from this repo and keep only the generator contract that makes the
module resolvable and testable.
