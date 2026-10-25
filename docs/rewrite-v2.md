# P0 v2 core

The `rewrite/v2` branch introduces a Python standard-library core. The legacy
Kotlin generator remains as historical/reference source while replacement
qualification proceeds. This is not an installed-release acceptance claim.

## Current executable surface

```sh
./p0 validate --catalog /path/to/p0-modules
./p0 plan --catalog /path/to/p0-modules --target keycloak
./p0 build --catalog /path/to/p0-modules --target keycloak --output /new/bundle
./p0 verify-bundle --bundle /new/bundle
./p0 status --state-dir /explicit/private/state
python3 -m unittest discover -s tests_v2 -v
```

Catalog layout is `modules/<module>/module.json`. Version 1 manifests declare
`schemaVersion`, `id`, and `services`. Services declare `id`, `runtime`, optional
pinned `image`, and `requires` entries with `service` and `kind`. Kinds are
`provision`, `order`, `ready`, and `integration`. Integration edges do not force
target closure or startup order. All referenced providers must exist in catalog.
Unknown fields, duplicate JSON keys/owners, mutable images and startup cycles fail.

A build requires immutable images for every selected service. Optional service
fields include `mounts`, `endpoints`, `probes`, `resources`, and argument-array
`command`. The renderer refuses arbitrary bind mounts, writable config, unscoped
public upstream ports, control-character injection and environment expansion.
Rootful public edge ports must be explicitly marked public. Build publication
never overwrites an existing destination. Bundle verification checks the exact
file set and hashes; it does not establish authenticity without an independently
trusted lock identity, or certify installation/application behavior.

Readiness edges remain explicit operation requirements, not `After=` theater.
Host-side TCP/HTTP observations have a total deadline, no application command
execution, no redirect/body logging, and require numeric IPs to avoid unbounded
stdlib DNS resolution. Network/address allocation must supply those addresses.

The operation journal uses transactional compare-and-swap revisions. Terminal
and indeterminate effects cannot be blindly restarted. Read-only status creates
nothing; a live WAL requiring a live reader is reported unknown, not presented
as an up-to-date checkpoint. Full live lifecycle integration is separate work.

## Runtime account bootstrap

`ops/host-admin/provision-p0-runtime.py` is a standalone, standard-library-only
Root bootstrap, not service Python. Execute only a private Root-owned,
hash-verified copy with `/usr/bin/python3 -I`. Default mode inventories only;
`--apply` explicitly creates/validates the sole `p0-runtime` account, private home,
new storage namespace and user-manager lingering. It does not touch old actors,
engines, policies or data. Existing wrong identities/modes fail closed. Fresh
home creation does not copy site-wide skeleton content. Account provisioning is
not a container installation or a service acceptance pass.

## Qualification boundaries

Current tests establish source/synthetic graph, rendering, bundle, journal,
deadline and account-guard behavior only. Remaining integration includes trusted
release handoff, image supply, resource provisioning, actual lifecycle/readiness,
SSO workflows and clean installed acceptance. Do not use rendered units directly
as a substitute for those checks or execute app-writable core code as Root.
