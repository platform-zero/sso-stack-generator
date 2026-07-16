# Module Inventory

This directory is the generator-owned inventory for active source and stack-module
repositories.

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

The `module-ci` group selects active stack-module repositories plus the
dual-purpose `test-runner` repository. It deliberately excludes unrelated source,
site, and generator repositories from the cross-repository composition job.

Module-specific service behavior belongs in the owning module repository under
`tests/contract.sh` or `tests/smoke.sh`. Generator tests should cover generic
schema, resolver, materialization, bundle, and deployed orchestration behavior.
