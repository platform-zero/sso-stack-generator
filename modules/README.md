# Module Inventory

This directory is the generator-owned inventory for active source and stack-module
repositories.

New site-lock modules use `module.json` (schema in `module.schema.json`). The
descriptor is module-local and declares explicit, versioned provided/required
capabilities, services/routes/volumes, configuration schema, allowed overlays,
and module verification commands. `site.lock.json` is the only site-level
composition authority; legacy manifests and generator pin files are not inputs
to `site-build.sh`.

- `catalog.json` is the master repository list.
- `groups/*.json` define generic pull groups for local development.
- `stack.module.schema.json` documents the metadata interface for a module repo.
- `scripts/pull-modules.sh` clones or fast-forwards repositories from these
  groups into a local workspace.
- `scripts/test-module.sh --all` and `scripts/test-module-group.sh --all`
  validate strict module metadata and run module-owned validation, contract, and
  declared smoke phases.

The catalog is not a site lock. Site-specific module selection and exact commit
pins belong in the site configuration repository.

The `destruction` group is local-only inventory for retired extraction remnants.
The pull helper reports those entries as skipped and does not clone them.

Module-specific service behavior belongs in the owning module repository under
`tests/contract.sh` or `tests/smoke.sh`. Generator tests should cover generic
schema, resolver, materialization, bundle, and deployed orchestration behavior.
