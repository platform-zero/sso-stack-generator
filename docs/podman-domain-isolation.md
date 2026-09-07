# Podman Linux-user domains

Platform Zero derives rootless Podman ownership from the site stack config's
`podman` section. A selected module must belong to exactly one rootless domain
or to `rootful_modules`; generation fails closed when ownership is missing or
duplicated.

The generated `podman-domains.json` is the account/install contract. It records
the Linux user and state, graph, and volume roots for each domain. The installer
uses that file instead of a built-in user list, installs each rendered service
environment only for its owner, and gives each rootless account a pruned release
containing only its Quadlets, environment templates, and referenced config
roots. Networks are emitted only for domains whose services use them.

Cross-domain `depends_on` edges must be allowed by the consumer domain's
`allow_dependencies` list. They are recorded in
`podman-domain-dependencies.json`; same-domain dependencies remain systemd unit
dependencies. Host loopback ingress remains separately recorded by
`podman-loopback-endpoints.json`.

## Maintenance workspaces

`maintenance-workspaces.json` maps the same domains to `stack_lab` Worklanes.
Plan materialization before applying it:

```sh
python3 ops/materialize-workspaces.py \
  --manifest maintenance-workspaces.json
```

After reviewing the JSON plan, run it as `stack_lab` with `--apply`. Existing
dirty, remote-drifted, or commit-drifted repositories stop the operation rather
than being reset.

`software-workspaces.json` is the parallel `software_lab` contract. Its nine
project paths, Worklane profile, CDI devices, boot policy, and reproducibility
commands are derived from site configuration. Plan and apply it with the same
materializer, running `--apply` as its declared owner. Paths outside the
declared root, unexpected ownership, changed profiles, changed instructions,
and repository drift fail closed.
Software-lane maintenance guidance is written below `.platform-zero/` so an
existing project-level `AGENTS.md` is never replaced.

The control-plane installer installs `platform-zero-worklanes.service` for each
declared owner. At login-manager startup it reads the owner's installed
manifest and starts only explicitly opted-in containers whose immutable
`io.worklane.id` and `io.worklane.name` labels match their lane manifest.
Linger is enabled so recovery does not require an interactive login.

Gerald's passwordless sudo is intentionally retained. The guarded
`finalize-access` broker action is not part of workspace installation or normal
activation.

## Host accounts

Account provisioning is root-owned and storage-gated:

```sh
sudo ops/provision-domain-accounts.sh \
  --domains podman-domains.json \
  --authorized-keys /root/platform-zero/maintenance-authorized-keys \
  --check
```

`--apply` creates missing accounts and storage. Existing service accounts keep
their current Podman graphroot unless `--migrate-existing` is supplied during a
planned data cutover. This prevents account preparation from silently hiding a
live rootless image store.
