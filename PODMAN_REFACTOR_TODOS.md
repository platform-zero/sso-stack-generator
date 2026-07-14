# Podman Refactor To-Dos

## Phase 0 — Split integration concerns (priority 1)
- [x] Extract caddy ownership from `latium-integrations-stack-module`.
  - Keep only Caddy runtime overlay + config in a dedicated caddy source (module or site-config artifact).
  - Remove caddy files from integration glue and update lock references accordingly.
  - Acceptance: generated bundle still emits `runtime.overlays/caddy.yml` and `stack.config/caddy/Caddyfile` with no functional change.

- [x] Unbundle `latium-integrations-stack-module` responsibilities.
  - The committed Podman manifest excludes the integration repository and uses the standalone Caddy module.
  - Retired repository audit: `components.json` was the old nested selection model; `stack.systemd/graph.json` is superseded by the Podman runtime graph; `global.settings/volumes.yml` is superseded by module runtime volume declarations; `service-contracts.json` is now represented by selected module contract fragments where still needed.
  - Removed stale `latium-integrations` and retired runtime module entries from the site compatibility locks.
  - Acceptance: integrations module no longer couples unrelated cross-cutting behavior into caddy concerns.

- [x] Split integration-specific logic currently in `site-config`.
  - Site config now selects the flat module set in `manifest.json`; compatibility lock artifacts mirror that selection and no longer carry retired runtime modules or integration glue.
  - Keep generated artifacts deterministic: `components`, `modules`, and lock data only.
  - Acceptance: equivalent rendered stack for same component selection.

- [x] Remove nested component composition from component selection model.
  - Replace transitive dependency expansion (`components.*.dependencies`) with explicit resolved component sets per profile.
  - Keep `components` as a flat include list (or equivalent manifest) with no nested dependency chains for runtime selection.
  - Acceptance: component selection output is deterministic and directly lists all included modules/runtime model files without graph indirection.

## Phase 1 — Runtime backend migration
- [x] Add runtime abstraction in generator.
  - Stop `compose` as canonical model; move render logic behind a backend interface.
  - Acceptance: same module input produces a Podman output bundle.

- [x] Implement Podman backend renderer using Quadlet/systemd.
  - Generate `.container`, `.network`, `.volume`, `.service`, `.timer` where applicable.
  - Replace runtime-unit shell wrapper dependencies on legacy container CLI abstractions.
  - Acceptance: deploy produces runnable podman-native systemd unit set for a representative component subset.

- [x] Remove retired runtime dependencies in generated/runtime path.
  - Replace socket-proxy/controller/lifecycle chain, watchtower/autoheal/health-exporter/dozzle/cadvisor/crowdsec-discovery dependencies with Podman-native replacements.
  - Acceptance: each replacement has equivalent or documented-better behavior notes.

- [x] Convert deferred controller/services with direct legacy container API assumptions.
  - JupyterHub and Forgejo runner use the rootless Podman socket in active runtime definitions.
  - Test-runner Kotlin and shell helpers default to Podman; retired testdev/labware paths are quarantined under `obsolete/`.
  - Acceptance: behavior parity where feasible; fallback strategy documented for any blockers.

## Phase 2 — Stack module cleanup
- [x] Remove retired runtime modules from active stack modules list.
  - Archive/replace modules that are now obsolete after podman migration.
  - Acceptance: non-archive active repo list matches active podman-capable module set.

- [x] Make module selection explicit via generator modules.
  - Ensure component selection and module catalog are source-of-truth; no hidden repo pulls.
  - Acceptance: single deterministic clone list per `site-config` lock.

## Phase 3 — Migration and rollout
- [x] Create dual-mode dry-run validation.
  - Validate runtime-model mode output and podman mode output from same model/commit.
  - Acceptance: parity checks on services, env keys, volume names, network names, and ingress routes.

- [x] Repair rootful Podman state attachment before rootless split.
  - Declare every named volume explicitly and remove generator fallback to `${STACK_VOLUME_ROOT}/<name>`.
  - Restore `jellyfin_media`, `qbittorrent_data`, `seafile_files`, `postgres_ssd_data`, and `opensearch_bind_data` to their canonical configured paths.
  - Move newly initialized incorrect stores under `/mnt/stack/quarantine` without deleting preserved container state.
  - Copy preserved Mastodon RSS state into explicit `/mnt/stack/volumes/mastodon_rss_publisher_state`.
  - Acceptance: live rootful stack runs against preserved PostgreSQL system ID `7656195858355810341`; OpenSearch starts on preserved data; Jellyfin, Seafile, and Mastodon RSS state sizes match preserved stores; no anonymous Podman volumes are attached.

- [x] Make the Podman runtime generator self-contained before rootless cutover.
  - Port or call the legacy `scripts/deploy/render-runtime.sh` template pass so `runtime/configs` contains rendered files, not only `*.template` sources.
  - Ensure generated bundles include required JVM build outputs or prebuilt local image artifacts instead of relying on prior releases.
  - Acceptance: activating a freshly generated Podman bundle requires no manual copy from an older release and leaves no missing bind sources in `journalctl`.

- [x] Perform rootless split with complete state persistence test.
  - Generate rootful and rootless Quadlet domains.
  - Keep Caddy, mailserver, node-exporter, Alloy, CrowdSec, Kopia, and host storage setup rootful.
  - Move remaining services under lingering `webservices` rootless user after ACL and namespace checks.
  - Replace Caddy container-DNS upstreams with generated loopback endpoints and publish rootless app endpoints on stable high localhost ports.
  - Acceptance: same-session cutover gate passes, including rollback proof, without a waiting window.

- [x] Document podman ops workflow.
  - Deployment, debugging, restart semantics, recovery, and migration notes.
  - Acceptance: ops docs and runbook updated in repo/docs.
